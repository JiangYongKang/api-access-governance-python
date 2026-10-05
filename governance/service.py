"""治理门面：组合凭证校验、配额（总量 + 滚动窗口）与审计，输出可解释判定。

判定顺序（短路）：
1. 凭证解析（格式/签名/撤销/过期/兼容窗口）
2. 权限范围检查（endpoint 所需的 scope）
3. 配额双层原子判定（总量层 → 窗口层，任意一层到顶即拒绝）
4. 追溯与审计：每一笔判定（放行或拒绝）都按 request_id 落 decision_trace；
   拒绝写 access_denied，放行写 access_allowed。策略或记账链路异常时
   本次请求一律拒绝（POLICY_FAILURE / AUDIT_FAILURE），绝不静默放行。
"""

from __future__ import annotations

import logging

from .audit import AuditLog
from .credentials import CredentialManager
from .errors import (
    AuditWriteError,
    DecisionReason,
    PolicyStoreError,
)
from .models import Decision
from .quota import QuotaLimiter

logger = logging.getLogger("governance")

# 命中的配额层 -> 判定原因
_LAYER_REASON = {
    "total": DecisionReason.QUOTA_EXCEEDED,
    "window": DecisionReason.RATE_LIMITED,
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
        """对一次请求做完整判定：凭证 -> 权限范围 -> 双层配额 -> 追溯/审计。"""
        try:
            cred, reason = self._credentials.resolve(token, now)
        except Exception as exc:  # noqa: BLE001 - 凭证链路任何异常都 fail-closed
            # 凭证链路（存储/解析）异常：fail-closed，绝不静默放行
            return self._short_circuit_deny(
                DecisionReason.POLICY_FAILURE, request_id, None, endpoint,
                f"credential resolution failure, request denied: {exc}", now)
        if cred is None:
            return self._short_circuit_deny(
                reason, request_id, None, endpoint,
                f"token rejected: {reason.value}", now)

        required = self._endpoint_scopes.get(endpoint)
        if required is not None and required not in cred.scopes:
            return self._short_circuit_deny(
                DecisionReason.INSUFFICIENT_SCOPE, request_id, cred.tenant_id, endpoint,
                f"endpoint {endpoint} requires scope '{required}'", now)

        # 双层配额原子判定（内部已落判定追溯）
        try:
            result = self._quota.acquire(cred.tenant_id, endpoint, request_id, now)
        except PolicyStoreError as exc:
            logger.warning("request_id=%s tenant=%s rule=policy_failure detail=%s",
                           request_id, cred.tenant_id, exc)
            return Decision(
                allowed=False, reason=DecisionReason.POLICY_FAILURE,
                request_id=request_id, tenant_id=cred.tenant_id,
                detail=f"policy/accounting failure, request denied: {exc}")

        if result.allowed:
            decision = Decision(
                allowed=True, reason=DecisionReason.ALLOWED, request_id=request_id,
                tenant_id=cred.tenant_id, detail="allowed",
                total_used=result.total_used, total_limit=result.total_limit,
                window_used=result.window_used, window_limit=result.window_limit,
                window_seconds=result.window_seconds, policy_source=result.policy_source,
                limiting_layer=None,
            )
            # 放行也留痕（access_allowed 审计）；审计失败则不放行
            try:
                self._audit.record(
                    "access_allowed", request_id, cred.tenant_id,
                    DecisionReason.ALLOWED.value, self._explain(result),
                    {"total_used": result.total_used, "total_limit": result.total_limit,
                     "window_used": result.window_used, "window_limit": result.window_limit,
                     "policy_source": result.policy_source},
                    now=now)
            except AuditWriteError as exc:
                logger.warning("request_id=%s tenant=%s rule=audit_failure detail=%s",
                               request_id, cred.tenant_id, exc)
                return Decision(
                    allowed=False, reason=DecisionReason.AUDIT_FAILURE,
                    request_id=request_id, tenant_id=cred.tenant_id,
                    detail=f"audit write failed, request denied: {exc}")
            logger.info("request_id=%s tenant=%s rule=allowed source=%s "
                        "total=%s/%s window=%s/%s@%ss",
                        request_id, cred.tenant_id, result.policy_source,
                        result.total_used, result.total_limit,
                        result.window_used, result.window_limit, result.window_seconds)
            return decision

        # 被某一层拦下：trace 已由原子事务写入，再补 access_denied 审计
        deny_reason = _LAYER_REASON[result.layer]
        decision = Decision(
            allowed=False, reason=deny_reason, request_id=request_id,
            tenant_id=cred.tenant_id, detail=result.detail,
            total_used=result.total_used, total_limit=result.total_limit,
            window_used=result.window_used, window_limit=result.window_limit,
            window_seconds=result.window_seconds, policy_source=result.policy_source,
            limiting_layer=result.layer,
        )
        try:
            self._audit.record("access_denied", request_id, cred.tenant_id,
                               deny_reason.value, result.detail,
                               {"layer": result.layer,
                                "total_used": result.total_used,
                                "total_limit": result.total_limit,
                                "window_used": result.window_used,
                                "window_limit": result.window_limit,
                                "policy_source": result.policy_source}, now=now)
        except AuditWriteError as exc:
            logger.warning("request_id=%s tenant=%s rule=audit_failure detail=%s",
                           request_id, cred.tenant_id, exc)
            return Decision(
                allowed=False, reason=DecisionReason.AUDIT_FAILURE,
                request_id=request_id, tenant_id=cred.tenant_id,
                detail=f"audit write failed, request denied: {exc}")
        logger.info("request_id=%s tenant=%s rule=%s layer=%s detail=%s",
                    request_id, cred.tenant_id, deny_reason.value,
                    result.layer, result.detail)
        return decision

    def _short_circuit_deny(self, reason: DecisionReason, request_id: str,
                           tenant_id: str | None, endpoint: str,
                           detail: str, now: float) -> Decision:
        """凭证/权限类拒绝：原子落盘判定追溯 + access_denied 审计。

        追溯或审计链路异常时，以 AUDIT_FAILURE 拒绝，绝不静默放行。
        """
        try:
            self._quota.record_denial(tenant_id or "-", endpoint, request_id,
                                      reason.value, detail, now)
        except AuditWriteError as exc:
            logger.warning("request_id=%s tenant=%s rule=audit_failure detail=%s",
                           request_id, tenant_id or "-", exc)
            return Decision(allowed=False, reason=DecisionReason.AUDIT_FAILURE,
                            request_id=request_id, tenant_id=tenant_id,
                            detail=f"audit write failed, request denied: {exc}")
        logger.info("request_id=%s tenant=%s rule=%s detail=%s",
                    request_id, tenant_id or "-", reason.value, detail)
        return Decision(allowed=False, reason=reason, request_id=request_id,
                        tenant_id=tenant_id, detail=detail)

    @staticmethod
    def _explain(result) -> str:
        return (f"source={result.policy_source} total={result.total_used}/"
                f"{result.total_limit} window={result.window_used}/"
                f"{result.window_limit}@{result.window_seconds:g}s")

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
