"""治理门面：组合凭证校验、配额与审计，输出可解释判定。

判定顺序（短路）：
1. 凭证解析（格式/签名/撤销/过期/兼容窗口）
2. 权限范围检查（endpoint 所需的 scope）
3. 配额原子扣减（放行才计数）
4. 审计：所有拒绝与凭证变更必留痕；审计写入失败时本次请求按
   AUDIT_FAILURE 拒绝，绝不静默放行。
"""

from __future__ import annotations

from .audit import AuditLog
from .credentials import CredentialManager
from .errors import AuditWriteError, DecisionReason
from .models import Decision
from .quota import QuotaLimiter


class GovernanceService:
    def __init__(self, credentials: CredentialManager, quota: QuotaLimiter, audit: AuditLog,
                 endpoint_scopes: dict[str, str] | None = None) -> None:
        self._credentials = credentials
        self._quota = quota
        self._audit = audit
        # endpoint -> 所需 scope；未配置的 endpoint 不强制 scope
        self._endpoint_scopes = dict(endpoint_scopes or {})

    def authorize(self, token: str, endpoint: str, request_id: str, now: float) -> Decision:
        """对一次请求做完整判定：凭证 -> 权限范围 -> 配额 -> 审计。"""
        cred, reason = self._credentials.resolve(token, now)
        if cred is None:
            return self._deny(reason, request_id, None, f"token rejected: {reason.value}", now)

        required = self._endpoint_scopes.get(endpoint)
        if required is not None and required not in cred.scopes:
            return self._deny(DecisionReason.INSUFFICIENT_SCOPE, request_id, cred.tenant_id,
                              f"endpoint {endpoint} requires scope '{required}'", now)

        if not self._quota.try_acquire(cred.tenant_id, endpoint, now):
            return self._deny(DecisionReason.QUOTA_EXCEEDED, request_id, cred.tenant_id,
                              f"quota exceeded for endpoint {endpoint}", now)

        return Decision(allowed=True, reason=DecisionReason.ALLOWED,
                        request_id=request_id, tenant_id=cred.tenant_id)

    def _deny(self, reason: DecisionReason, request_id: str, tenant_id: str | None,
              detail: str, now: float) -> Decision:
        """记录拒绝审计并返回拒绝结论；审计失败时以 AUDIT_FAILURE 拒绝。"""
        try:
            self._audit.record("access_denied", request_id, tenant_id or "-",
                               reason.value, detail, now=now)
        except AuditWriteError as exc:
            return Decision(allowed=False, reason=DecisionReason.AUDIT_FAILURE,
                            request_id=request_id, tenant_id=tenant_id,
                            detail=f"audit write failed, request denied: {exc}")
        return Decision(allowed=False, reason=reason, request_id=request_id,
                        tenant_id=tenant_id, detail=detail)

    # ---- 凭证生命周期（带审计） ----
    def issue_credential(self, tenant_id: str, scopes: set[str], ttl_seconds: float,
                         request_id: str, now: float) -> str:
        token, cred = self._credentials.issue(tenant_id, scopes, ttl_seconds, now)
        self._audit.record("credential_issued", request_id, tenant_id, "issued",
                           f"key_id={cred.key_id}", {"key_id": cred.key_id, "scopes": sorted(scopes)}, now=now)
        return token

    def rotate_credential(self, key_id: str, request_id: str, now: float) -> str:
        token, new_cred = self._credentials.rotate(key_id, now)
        self._audit.record("credential_rotated", request_id, new_cred.tenant_id, "rotated",
                           f"old={key_id} new={new_cred.key_id}",
                           {"old_key_id": key_id, "new_key_id": new_cred.key_id}, now=now)
        return token

    def revoke_credential(self, key_id: str, tenant_id: str, request_id: str, now: float) -> None:
        self._credentials.revoke(key_id, now)
        self._audit.record("credential_revoked", request_id, tenant_id, "revoked",
                           f"key_id={key_id}", {"key_id": key_id}, now=now)
