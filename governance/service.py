"""治理门面：组合凭证校验、配额（总量 + 滚动窗口）与审计，输出可解释判定。

判定顺序（短路）：
1. 凭证解析（格式/签名/撤销/过期/兼容窗口）
2. 权限范围检查（endpoint 所需的 scope）
3. 配额原子判定（总量层与滚动窗口层，任一层到顶即拒绝；放行才计数，
   且放行审计与两层计数在同一存储事务内提交）
4. 审计：所有判定（放行/拒绝）与凭证、策略变更必留痕。

Fail-closed：凭证之后的策略读取、记账或审计链路一旦异常，本次请求一律按
``quota_unavailable`` / ``audit_failure`` 拒绝，绝不静默放行。
"""

from __future__ import annotations

from .audit import AuditLog
from .credentials import CredentialManager
from .errors import AuditWriteError, DecisionReason, QuotaError
from .models import Decision, QuotaPolicy
from .quota import QuotaLimiter

# 配额拒绝层 -> 判定原因
_LAYER_REASONS = {
    "total": DecisionReason.QUOTA_EXCEEDED,
    "window": DecisionReason.QUOTA_WINDOW_EXCEEDED,
}


class GovernanceService:
    def __init__(self, credentials: CredentialManager, quota: QuotaLimiter, audit: AuditLog,
                 endpoint_scopes: dict[str, str] | None = None) -> None:
        self._credentials = credentials
        self._quota = quota
        self._audit = audit
        # endpoint -> 所需 scope；未配置的 endpoint 不强制 scope
        self._endpoint_scopes = dict(endpoint_scopes or {})

    def authorize(self, token: str, endpoint: str, request_id: str, now: float) -> Decision:
        """对一次请求做完整判定：凭证 -> 权限范围 -> 配额（两层）-> 审计。"""
        cred, reason = self._credentials.resolve(token, now)
        if cred is None:
            return self._deny(reason, request_id, None, f"token rejected: {reason.value}", now)

        required = self._endpoint_scopes.get(endpoint)
        if required is not None and required not in cred.scopes:
            return self._deny(DecisionReason.INSUFFICIENT_SCOPE, request_id, cred.tenant_id,
                              f"endpoint {endpoint} requires scope '{required}'", now)

        try:
            result = self._quota.acquire(cred.tenant_id, endpoint, request_id, now)
        except QuotaError as exc:
            # 策略/记账链路故障：拒绝放行；审计本身也可能不可用，best-effort 留痕
            return self._deny(DecisionReason.QUOTA_UNAVAILABLE, request_id, cred.tenant_id,
                              f"quota chain failed, request denied: {exc}", now)

        if not result.allowed:
            reason = _LAYER_REASONS.get(result.layer, DecisionReason.QUOTA_EXCEEDED)
            snap = result.snapshot
            if result.layer == "window":
                detail = (f"rolling window quota exceeded: {snap.window_used}/"
                          f"{snap.window_limit} in {snap.window_seconds}s "
                          f"(policy source={result.policy_source})")
            else:
                detail = (f"total quota exceeded: {snap.total_used}/{snap.total_limit}"
                          f" on endpoint {endpoint} (policy source={result.policy_source})")
            return self._deny(reason, request_id, cred.tenant_id, detail, now,
                              extra=self._snapshot_extra(result))

        # 放行审计（access_allowed 与计数已在同一事务内落盘，这里只组装结论）
        return Decision(allowed=True, reason=DecisionReason.ALLOWED,
                        request_id=request_id, tenant_id=cred.tenant_id,
                        extra=self._snapshot_extra(result))

    def _deny(self, reason: DecisionReason, request_id: str, tenant_id: str | None,
              detail: str, now: float, extra: dict | None = None) -> Decision:
        """记录拒绝审计并返回拒绝结论；审计失败时以 AUDIT_FAILURE 拒绝。"""
        try:
            self._audit.record("access_denied", request_id, tenant_id or "-",
                               reason.value, detail, extra or {}, now=now)
        except AuditWriteError as exc:
            return Decision(allowed=False, reason=DecisionReason.AUDIT_FAILURE,
                            request_id=request_id, tenant_id=tenant_id,
                            detail=f"audit write failed, request denied: {exc}")
        return Decision(allowed=False, reason=reason, request_id=request_id,
                        tenant_id=tenant_id, detail=detail, extra=extra or {})

    @staticmethod
    def _snapshot_extra(result) -> dict:
        """把命中策略、用量与上限快照转成可追溯的 extra。"""
        snap = result.snapshot
        policy = result.policy
        return {
            "policy_tenant_id": policy.tenant_id if policy else None,
            "policy_source": result.policy_source,
            "layer": result.layer,
            "total_limit": snap.total_limit,
            "total_used": snap.total_used,
            "window_limit": snap.window_limit,
            "window_seconds": snap.window_seconds,
            "window_used": snap.window_used,
        }

    # ---- 配额策略管理（管理员接口，持久化 + 留痕） ----
    def set_quota_policy(self, policy: QuotaPolicy, request_id: str, now: float) -> None:
        """下发/调整策略（含 tenant_id="*" 默认策略）；先校验再持久化再留痕。"""
        # put_policy 内部会做校验；持久化失败上抛 QuotaError（由接口层转 5xx，不算成功）
        self._quota.put_policy(policy)
        self._audit.record(
            "quota_policy_set", request_id, policy.tenant_id, "policy_set",
            f"endpoint={policy.endpoint} total={policy.total_limit} "
            f"window={policy.window_limit}/{policy.window_seconds}s",
            {
                "tenant_id": policy.tenant_id,
                "endpoint": policy.endpoint,
                "total_limit": policy.total_limit,
                "window_limit": policy.window_limit,
                "window_seconds": policy.window_seconds,
                "updated_at": policy.updated_at,
            },
            now=now)

    def get_quota_status(self, tenant_id: str, endpoint: str, now: float) -> dict:
        """查询当前真正生效的上限与已用量（含策略来源）。"""
        return self._quota.status(tenant_id, endpoint, now)

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
