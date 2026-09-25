"""本地 HTTP 服务：在演示接口上挂载多租户访问控制与配额治理。

接口:
- GET  /                       健康检查
- POST /admin/credentials      签发凭证（body: tenant, scopes, ttl_seconds?）
- POST /admin/credentials/{id}/rotate    轮换凭证（body: grace_period?）
- POST /admin/credentials/{id}/revoke    撤销凭证（body: grace_period?）
- GET  /admin/credentials       查询凭证列表（?tenant=）（不返回秘密/哈希）
- PUT  /admin/quotas            设置配额（tenant, endpoint, limit, window_seconds）
- GET  /admin/quotas            查询配额（?tenant=&endpoint=）
- GET  /admin/audit             查询审计流水（?tenant=&request_id=&decision=&limit=）
- GET  /tenant/data             受保护接口（需 scope=read:data，受配额限制）

所有拒绝返回 JSON:
    {"error": code, "rule": ..., "detail": ..., "request_id": ...}
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from governance.audit import AuditLog
from governance.errors import GovernanceError
from governance.model import QuotaState
from governance.persistence import GovernanceStore
from governance.service import GovernanceService

DATA_DIR = Path(os.environ.get("GOVERNANCE_DIR", ".data"))
ENDPOINT_DATA = "GET /tenant/data"
SCOPE_DATA = "read:data"

service: GovernanceService | None = None


def get_service() -> GovernanceService:
    """返回启动时初始化的全局治理服务。"""
    if service is None:
        raise RuntimeError("治理服务尚未初始化")
    return service


@asynccontextmanager
async def lifespan(app: FastAPI):
    global service
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    store = GovernanceStore(DATA_DIR / "state.json")
    store.load()
    service = GovernanceService(store, AuditLog(DATA_DIR / "audit.jsonl"))
    yield


app = FastAPI(title="API Access Governance (local)", lifespan=lifespan)


# ---- 请求/响应模型 ----------------------------------------------------


class IssueRequest(BaseModel):
    tenant: str = Field(min_length=1)
    scopes: list[str] = Field(default_factory=list)
    ttl_seconds: float | None = None


class RotateRequest(BaseModel):
    grace_period: float = 0.0


class RevokeRequest(BaseModel):
    grace_period: float = 0.0


class QuotaRequest(BaseModel):
    tenant: str = Field(min_length=1)
    endpoint: str = Field(min_length=1)
    limit: int = Field(ge=0)
    window_seconds: float = Field(gt=0)


@app.exception_handler(GovernanceError)
def _governance_error_handler(request: Request, exc: GovernanceError) -> JSONResponse:
    # 审计失败按 500，其余判定类拒绝按 403；缺凭证按 401。
    status = 403
    if exc.reason.value == "audit_failure":
        status = 500
    elif exc.reason.value == "missing_credential":
        status = 401
    return JSONResponse(
        status_code=status,
        content={
            "error": exc.reason.value,
            "rule": exc.rule,
            "detail": exc.detail,
            "request_id": exc.request_id,
        },
    )


@app.get("/")
def read_root() -> dict[str, str]:
    return {"status": "ok"}


# ---- 凭证管理 ---------------------------------------------------------


@app.post("/admin/credentials", status_code=201)
def issue_credential(body: IssueRequest, request: Request) -> dict[str, object]:
    svc = get_service()
    rid = request.headers.get("x-request-id") or svc.new_request_id()
    credential_id, token = svc.issue_credential(
        body.tenant, set(body.scopes), body.ttl_seconds, request_id=rid
    )
    return {
        "request_id": rid,
        "credential_id": credential_id,
        "token": token,
        "detail": "请妥善保存 token，服务端只留存其哈希",
    }


@app.post("/admin/credentials/{credential_id}/rotate")
def rotate_credential(
    credential_id: str, body: RotateRequest, request: Request
) -> dict[str, object]:
    svc = get_service()
    rid = request.headers.get("x-request-id") or svc.new_request_id()
    new_id, token = svc.rotate_credential(
        credential_id, body.grace_period, request_id=rid
    )
    return {
        "request_id": rid,
        "old_credential_id": credential_id,
        "credential_id": new_id,
        "token": token,
        "grace_period": body.grace_period,
    }


@app.post("/admin/credentials/{credential_id}/revoke")
def revoke_credential(
    credential_id: str, body: RevokeRequest, request: Request
) -> dict[str, object]:
    svc = get_service()
    rid = request.headers.get("x-request-id") or svc.new_request_id()
    svc.revoke_credential(credential_id, body.grace_period, request_id=rid)
    return {
        "request_id": rid,
        "credential_id": credential_id,
        "revoked": True,
        "grace_period": body.grace_period,
    }


@app.get("/admin/credentials")
def list_credentials(tenant: str | None = None) -> dict[str, object]:
    svc = get_service()
    return {
        "credentials": [
            {
                "credential_id": r.credential_id,
                "tenant": r.tenant,
                "scopes": sorted(r.scopes),
                "version": r.version,
                "issued_at": r.issued_at,
                "expires_at": r.expires_at,
                "revoked_at": r.revoked_at,
                "grace_until": r.grace_until,
                "superseded_by": r.superseded_by,
            }
            for r in svc.credentials._store.list_credentials(tenant)
        ]
    }


# ---- 配额管理 ---------------------------------------------------------


def _quota_dict(q: QuotaState) -> dict[str, object]:
    return {
        "tenant": q.tenant,
        "endpoint": q.endpoint,
        "limit": q.limit,
        "window_seconds": q.window_seconds,
        "used": q.used,
        "window_start": q.window_start,
    }


@app.put("/admin/quotas")
def set_quota(body: QuotaRequest) -> dict[str, object]:
    svc = get_service()
    state = svc.quotas.set_limit(
        body.tenant, body.endpoint, body.limit, body.window_seconds
    )
    return _quota_dict(state)


@app.get("/admin/quotas")
def get_quota(tenant: str | None = None, endpoint: str | None = None) -> dict[str, object]:
    svc = get_service()
    quotas = svc.quotas._store.all_quotas()
    if tenant is not None:
        quotas = [q for q in quotas if q.tenant == tenant]
    if endpoint is not None:
        quotas = [q for q in quotas if q.endpoint == endpoint]
    return {"quotas": [_quota_dict(q) for q in quotas]}


# ---- 审计查询 ---------------------------------------------------------


@app.get("/admin/audit")
def query_audit(
    tenant: str | None = None,
    request_id: str | None = None,
    decision: str | None = None,
    limit: int = 100,
) -> dict[str, object]:
    svc = get_service()
    entries = svc.audit.query(
        tenant=tenant, request_id=request_id, decision=decision, limit=limit
    )
    return {
        "entries": [
            {
                "request_id": e.request_id,
                "timestamp": e.timestamp,
                "tenant": e.tenant,
                "endpoint": e.endpoint,
                "decision": e.decision,
                "rule": e.rule,
                "reason": e.reason,
                "detail": e.detail,
                "credential_id": e.credential_id,
                "quota_used": e.quota_used,
                "quota_limit": e.quota_limit,
            }
            for e in entries
        ]
    }


# ---- 受保护业务接口 ---------------------------------------------------


@app.get("/tenant/data")
def read_tenant_data(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    svc = get_service()
    rid = request.headers.get("x-request-id") or svc.new_request_id()
    decision = svc.authorize(
        token=authorization,
        endpoint=ENDPOINT_DATA,
        required_scope=SCOPE_DATA,
        request_id=rid,
    )
    return {
        "request_id": rid,
        "tenant": decision.tenant,
        "credential_id": decision.credential_id,
        "rule": decision.rule,
        "detail": decision.detail,
        "data": "这里是租户专属业务数据",
    }
