"""本地 HTTP 服务：多租户访问控制与配额治理（总量 + 滚动窗口，策略持久化）。

端点：
- POST /credentials                 签发凭证 {tenant_id, scopes, ttl_seconds}
- POST /credentials/{key_id}/rotate 轮换（旧凭证进入兼容窗口）
- POST /credentials/{key_id}/revoke 撤销（立即生效）
- GET  /data                        受保护资源（需 Authorization: Bearer <token>，scope=read）
- PUT  /quota/policies              下发/调整配额策略（tenant_id="*" 为默认策略）
- PUT  /quota/limits                兼容旧用法：仅设置总量上限
- GET  /quota/status                查询当前真正生效的上限与已用量
- GET  /quota/{tenant_id}           兼容旧用法：查询总量已用
- GET  /audit                       查询审计流水（可按 tenant_id / event / request_id 过滤）
"""

import time

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from governance.audit import AuditLog, new_request_id
from governance.credentials import CredentialManager
from governance.errors import DecisionReason, QuotaError
from governance.models import QuotaPolicy
from governance.quota import QuotaLimiter
from governance.service import GovernanceService
from governance.storage import DEFAULT_POLICY_TENANT, Storage

DB_PATH = "governance.db"
PROTECTED_ENDPOINT = "/data"
DEFAULT_LIMIT = 100

storage = Storage(DB_PATH)
service = GovernanceService(
    credentials=CredentialManager(storage),
    quota=QuotaLimiter(storage),
    audit=AuditLog(storage),
    endpoint_scopes={PROTECTED_ENDPOINT: "read"},
)


def _seed_default_policy() -> None:
    """启动时幂等种入文档化的默认总量上限。

    只在尚无默认策略时写入：管理员之后通过接口调整的默认策略会持久化，
    重启不会被这里的种子值覆盖。
    """
    existing = storage.get_quota_policy(DEFAULT_POLICY_TENANT, PROTECTED_ENDPOINT)
    if existing is None:
        service.set_quota_policy(
            QuotaPolicy(tenant_id=DEFAULT_POLICY_TENANT, endpoint=PROTECTED_ENDPOINT,
                        total_limit=DEFAULT_LIMIT, window_limit=None, window_seconds=None,
                        updated_at=time.time()),
            request_id="bootstrap-default-policy", now=time.time())


_seed_default_policy()

app = FastAPI(title="API Access Governance")


class IssueRequest(BaseModel):
    tenant_id: str
    scopes: list[str]
    ttl_seconds: float = 3600.0


class QuotaLimitRequest(BaseModel):
    tenant_id: str
    endpoint: str
    limit: int


class QuotaPolicyRequest(BaseModel):
    tenant_id: str
    endpoint: str
    total_limit: int | None = None
    window_limit: int | None = None
    window_seconds: float | None = None


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/credentials", status_code=201)
def issue_credential(req: IssueRequest):
    token = service.issue_credential(req.tenant_id, set(req.scopes), req.ttl_seconds,
                                     new_request_id(), time.time())
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


@app.put("/quota/policies", status_code=204)
def set_quota_policy(req: QuotaPolicyRequest):
    """管理员下发/调整策略：可同时给总量上限与滚动窗口；tenant_id="*" 为默认策略。"""
    policy = QuotaPolicy(
        tenant_id=req.tenant_id, endpoint=req.endpoint, total_limit=req.total_limit,
        window_limit=req.window_limit, window_seconds=req.window_seconds,
        updated_at=time.time())
    try:
        service.set_quota_policy(policy, new_request_id(), time.time())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except QuotaError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.put("/quota/limits", status_code=204)
def set_quota_limit(req: QuotaLimitRequest):
    """兼容旧用法：仅覆盖总量上限（保留已配置的窗口层）。"""
    try:
        service._quota.set_limit(req.tenant_id, req.endpoint, req.limit, now=time.time())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except QuotaError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/quota/status")
def get_quota_status(tenant_id: str, endpoint: str = PROTECTED_ENDPOINT):
    """查询当前真正生效的上限与已用量（含策略来源 exact/default/none）。"""
    try:
        return service.get_quota_status(tenant_id, endpoint, time.time())
    except QuotaError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/quota/{tenant_id}")
def get_quota(tenant_id: str, endpoint: str = PROTECTED_ENDPOINT):
    try:
        status = service.get_quota_status(tenant_id, endpoint, time.time())
    except QuotaError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"tenant_id": tenant_id, "endpoint": endpoint,
            "used": status["total_used"]}


@app.get("/data")
def get_data(authorization: str = Header(default="")):
    request_id = new_request_id()
    token = authorization.removeprefix("Bearer ").strip()
    decision = service.authorize(token, PROTECTED_ENDPOINT, request_id, time.time())
    if not decision.allowed:
        if decision.reason is DecisionReason.QUOTA_EXCEEDED \
                or decision.reason is DecisionReason.QUOTA_WINDOW_EXCEEDED:
            status_code = 429
        elif decision.reason is DecisionReason.QUOTA_UNAVAILABLE:
            status_code = 503
        else:
            status_code = 403
        raise HTTPException(status_code=status_code, detail={
            "request_id": decision.request_id,
            "reason": decision.reason.value,
            "detail": decision.detail,
            "snapshot": decision.extra,
        })
    return {"request_id": request_id, "tenant_id": decision.tenant_id,
            "data": "secret-data", "snapshot": decision.extra}


@app.get("/audit")
def get_audit(tenant_id: str | None = None, event: str | None = None,
              request_id: str | None = None):
    records = service._audit.query(tenant_id=tenant_id, event=event)
    if request_id is not None:
        records = [r for r in records if r.request_id == request_id]
    return {"records": [
        {"seq": r.seq, "ts": r.ts, "event": r.event, "request_id": r.request_id,
         "tenant_id": r.tenant_id, "reason": r.reason, "detail": r.detail, "extra": r.extra}
        for r in records
    ]}
