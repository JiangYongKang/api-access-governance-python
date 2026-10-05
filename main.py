"""本地 HTTP 服务：多租户访问控制与配额治理（持久化策略 + 总量/滚动窗口双层限制）。

端点：
- POST /credentials                 签发凭证 {tenant_id, scopes, ttl_seconds}
- POST /credentials/{key_id}/rotate 轮换（旧凭证进入兼容窗口）
- POST /credentials/{key_id}/revoke 撤销（立即生效）
- GET  /data                        受保护资源（需 Authorization: Bearer <token>，scope=read）
- PUT  /quota/limits                兼容旧接口：仅调整总量上限（保留窗口配置）
- PUT  /quota/policies              下发/覆盖租户×接口策略（tenant_id="*" 为默认策略）
- GET  /quota/policies              列出已落盘策略（可按 endpoint 过滤）
- GET  /quota/{tenant_id}           查询当前真正生效的上限与已用量
- GET  /decisions/{request_id}      按请求标识查判定快照（放行/拒绝均可追溯）
- GET  /audit                       查询审计流水（可按 tenant_id / event 过滤）
"""

import logging
import os
import time

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from governance.audit import AuditLog, new_request_id
from governance.credentials import CredentialManager
from governance.errors import DecisionReason
from governance.quota import QuotaLimiter
from governance.service import GovernanceService
from governance.storage import DEFAULT_TENANT, Storage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

DB_PATH = os.environ.get("GOVERNANCE_DB", "governance.db")
PROTECTED_ENDPOINT = "/data"
DEFAULT_LIMIT = 100


def create_app(db_path: str = DB_PATH) -> FastAPI:
    """装配一个使用独立数据库文件的应用实例（便于测试与多环境部署）。"""
    storage = Storage(db_path)
    service = GovernanceService(
        credentials=CredentialManager(storage),
        quota=QuotaLimiter(storage),
        audit=AuditLog(storage),
        endpoint_scopes={PROTECTED_ENDPOINT: "read"},
    )
    # 文档化的默认总量上限示例：对未单独配置的租户明确生效；启动重复执行是覆盖语义
    service._quota.set_policy(DEFAULT_TENANT, PROTECTED_ENDPOINT,
                              total_limit=DEFAULT_LIMIT)

    app = FastAPI(title="API Access Governance")

    class IssueRequest(BaseModel):
        tenant_id: str
        scopes: list[str]
        ttl_seconds: float = 3600.0

    class LimitRequest(BaseModel):
        tenant_id: str
        endpoint: str
        limit: int

    class PolicyRequest(BaseModel):
        tenant_id: str = Field(description='租户标识；"*" 表示默认策略')
        endpoint: str
        total_limit: int | None = Field(default=None, ge=0,
                                        description="累计总量上限；null 表示总量层不限制")
        window_seconds: float = Field(default=0.0, ge=0.0,
                                      description="滚动窗口长度（秒），>0 时窗口层生效")
        window_limit: int | None = Field(default=None, ge=1,
                                         description="窗口内最大次数；null 表示窗口层不限制")

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    @app.post("/credentials", status_code=201)
    def issue_credential(req: IssueRequest):
        token = service.issue_credential(req.tenant_id, set(req.scopes),
                                         req.ttl_seconds, new_request_id(), time.time())
        return {"token": token}

    @app.post("/credentials/{key_id}/rotate")
    def rotate_credential(key_id: str):
        try:
            token = service.rotate_credential(key_id, new_request_id(), time.time())
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return {"token": token}

    @app.post("/credentials/{key_id}/revoke")
    def revoke_credential(key_id: str, tenant_id: str = ""):
        try:
            service.revoke_credential(key_id, tenant_id, new_request_id(), time.time())
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return {"revoked": key_id}

    @app.put("/quota/limits", status_code=204)
    def put_quota_limit(req: LimitRequest):
        """兼容旧接口：只调整总量上限（保留已有窗口配置），并持久化。"""
        service._quota.set_limit(req.tenant_id, req.endpoint, req.limit)

    @app.put("/quota/policies", status_code=200)
    def put_quota_policy(req: PolicyRequest):
        """下发/覆盖策略。整条覆盖：同一 key 反复下发以最后一次为准。"""
        try:
            policy = service._quota.set_policy(
                req.tenant_id, req.endpoint, req.total_limit,
                req.window_seconds, req.window_limit)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return {
            "tenant_id": policy.tenant_id, "endpoint": policy.endpoint,
            "total_limit": policy.total_limit,
            "window_seconds": policy.window_seconds or None,
            "window_limit": policy.window_limit,
            "updated_at": policy.updated_at,
        }

    @app.get("/quota/policies")
    def list_quota_policies(endpoint: str | None = None):
        return {"policies": [
            {"tenant_id": p.tenant_id, "endpoint": p.endpoint,
             "total_limit": p.total_limit,
             "window_seconds": p.window_seconds or None,
             "window_limit": p.window_limit, "updated_at": p.updated_at}
            for p in storage.list_policies(endpoint=endpoint)
        ]}

    @app.get("/quota/{tenant_id}")
    def get_quota(tenant_id: str, endpoint: str = PROTECTED_ENDPOINT):
        """当前真正生效的上限与已用量（含策略来源 tenant/default/none）。"""
        return service._quota.status(tenant_id, endpoint, time.time())

    @app.get("/decisions/{request_id}")
    def get_decision(request_id: str):
        snap = service._quota.get_decision(request_id)
        if snap is None:
            raise HTTPException(status_code=404,
                                detail=f"no decision for request_id={request_id}")
        return snap

    @app.get("/data")
    def get_data(authorization: str = Header(default="")):
        request_id = new_request_id()
        token = authorization.removeprefix("Bearer ").strip()
        decision = service.authorize(token, PROTECTED_ENDPOINT, request_id, time.time())
        if not decision.allowed:
            if decision.reason in (DecisionReason.QUOTA_EXCEEDED,
                                   DecisionReason.RATE_LIMITED):
                status = 429
            else:
                status = 403
            raise HTTPException(status_code=status, detail={
                "request_id": decision.request_id,
                "reason": decision.reason.value,
                "detail": decision.detail,
                "limiting_layer": decision.limiting_layer,
            })
        return {"request_id": request_id, "tenant_id": decision.tenant_id,
                "data": "secret-data"}

    @app.get("/audit")
    def get_audit(tenant_id: str | None = None, event: str | None = None):
        records = service._audit.query(tenant_id=tenant_id, event=event)
        return {"records": [
            {"seq": r.seq, "ts": r.ts, "event": r.event, "request_id": r.request_id,
             "tenant_id": r.tenant_id, "reason": r.reason, "detail": r.detail,
             "extra": r.extra}
            for r in records
        ]}

    return app


app = create_app(DB_PATH)
