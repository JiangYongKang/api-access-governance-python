"""本地 HTTP 服务：多租户访问控制与配额治理。

端点：
- POST /credentials                 签发凭证 {tenant_id, scopes, ttl_seconds}
- POST /credentials/{key_id}/rotate 轮换（旧凭证进入兼容窗口）
- POST /credentials/{key_id}/revoke 撤销（立即生效）
- GET  /data                        受保护资源（需 Authorization: Bearer <token>，scope=read）
- GET  /quota/{tenant_id}           查询配额用量
- GET  /audit                       查询审计流水（可按 tenant_id / event 过滤）
"""

import time

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from governance.audit import AuditLog, new_request_id
from governance.credentials import CredentialManager
from governance.errors import DecisionReason
from governance.quota import QuotaLimiter
from governance.service import GovernanceService
from governance.storage import Storage

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
service._quota.set_limit("*", PROTECTED_ENDPOINT, DEFAULT_LIMIT)  # 文档化的默认上限示例

app = FastAPI(title="API Access Governance")


class IssueRequest(BaseModel):
    tenant_id: str
    scopes: list[str]
    ttl_seconds: float = 3600.0


class QuotaLimitRequest(BaseModel):
    tenant_id: str
    endpoint: str
    limit: int


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


@app.put("/quota/limits", status_code=204)
def set_quota_limit(req: QuotaLimitRequest):
    service._quota.set_limit(req.tenant_id, req.endpoint, req.limit)


@app.get("/quota/{tenant_id}")
def get_quota(tenant_id: str, endpoint: str = PROTECTED_ENDPOINT):
    return {"tenant_id": tenant_id, "endpoint": endpoint,
            "used": service._quota.usage(tenant_id, endpoint)}


@app.get("/data")
def get_data(authorization: str = Header(default="")):
    request_id = new_request_id()
    token = authorization.removeprefix("Bearer ").strip()
    decision = service.authorize(token, PROTECTED_ENDPOINT, request_id, time.time())
    if not decision.allowed:
        status = 429 if decision.reason is DecisionReason.QUOTA_EXCEEDED else 403
        raise HTTPException(status_code=status, detail={
            "request_id": decision.request_id,
            "reason": decision.reason.value,
            "detail": decision.detail,
        })
    return {"request_id": request_id, "tenant_id": decision.tenant_id, "data": "secret-data"}


@app.get("/audit")
def get_audit(tenant_id: str | None = None, event: str | None = None):
    records = service._audit.query(tenant_id=tenant_id, event=event)
    return {"records": [
        {"seq": r.seq, "ts": r.ts, "event": r.event, "request_id": r.request_id,
         "tenant_id": r.tenant_id, "reason": r.reason, "detail": r.detail, "extra": r.extra}
        for r in records
    ]}
