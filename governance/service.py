"""授权门面：编排认证、配额与审计，保证判定结论一致且可解释。

一次 ``authorize`` 的关键顺序（全部在 store 锁内，审计先行、配额后提交）::

    1. 认证 + 权限范围检查（CredentialService.authenticate）
       失败 -> 写拒绝审计（审计失败则按 AUDIT_FAILURE 拒绝）-> 抛 GovernanceError
    2. 配额只读评估（QuotaManager.evaluate），仅做内存投影，不落盘
       耗尽 -> 写拒绝审计 -> 抛 GovernanceError（拒绝永不计数）
    3. 先写"放行"审计并 fsync，再 QuotaManager.commit 提交配额并落盘
       审计写失败 -> 不提交配额 -> AUDIT_FAILURE 拒绝
       提交失败（防御性）-> 补写一条同 request_id 的拒绝审计 -> AUDIT_FAILURE 拒绝

因此只有"认证通过且配额投影可放行且审计落盘成功且配额提交成功"的请求
才会被放行，配额计数与审计中的放行记录严格一一对应，不存在幽灵配额，
审计异常也绝不会静默放行。
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable

from governance.audit import AuditLog
from governance.credentials import CredentialService
from governance.errors import AuditError, DenyReason, GovernanceError
from governance.model import AuditEntry, AuthDecision
from governance.persistence import GovernanceStore
from governance.quota import QuotaExceeded, QuotaManager


class GovernanceService:
    """认证 + 配额 + 审计的统一编排入口。"""

    def __init__(
        self,
        store: GovernanceStore,
        audit: AuditLog,
        clock: Callable[[], float] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._store = store
        self._audit = audit
        self._clock = clock or time.time
        self._id_factory = id_factory or (lambda: "req-" + uuid.uuid4().hex)
        self._credentials = CredentialService(store, clock=self._clock)
        self._quotas = QuotaManager(store, clock=self._clock)

    @property
    def credentials(self) -> CredentialService:
        return self._credentials

    @property
    def quotas(self) -> QuotaManager:
        return self._quotas

    @property
    def audit(self) -> AuditLog:
        return self._audit

    def new_request_id(self) -> str:
        """生成请求标识。"""
        return self._id_factory()

    # ---- 凭证生命周期（带审计） -------------------------------------

    def issue_credential(
        self,
        tenant: str,
        scopes: set[str] | frozenset[str],
        ttl_seconds: float | None = None,
        request_id: str | None = None,
    ) -> tuple[str, str]:
        """签发凭证并写审计；返回 (credential_id, 明文 token)。"""
        rid = request_id or self.new_request_id()
        credential_id, plaintext = self._credentials.issue(
            tenant, scopes, ttl_seconds
        )
        self._audit.append(
            AuditEntry(
                request_id=rid,
                timestamp=self._clock(),
                tenant=tenant,
                endpoint="admin:issue_credential",
                decision="credential_issued",
                rule="credential.issue",
                detail=(
                    f"签发凭证 version=1 scopes={sorted(frozenset(scopes))}"
                    + (f" ttl_seconds={ttl_seconds}" if ttl_seconds is not None else "")
                ),
                credential_id=credential_id,
            )
        )
        return credential_id, plaintext

    def rotate_credential(
        self,
        credential_id: str,
        grace_period: float = 0.0,
        request_id: str | None = None,
    ) -> tuple[str, str]:
        """轮换凭证（旧凭证进入兼容窗口）并写审计。"""
        rid = request_id or self.new_request_id()
        new_id, plaintext = self._credentials.rotate(credential_id, grace_period)
        self._audit.append(
            AuditEntry(
                request_id=rid,
                timestamp=self._clock(),
                tenant=self._tenant_of(new_id),
                endpoint="admin:rotate_credential",
                decision="credential_rotated",
                rule="credential.rotate",
                detail=(
                    f"轮换 {credential_id} -> {new_id}，"
                    f"旧凭证兼容窗口 grace_period={grace_period}s"
                ),
                credential_id=new_id,
            )
        )
        return new_id, plaintext

    def revoke_credential(
        self,
        credential_id: str,
        grace_period: float = 0.0,
        request_id: str | None = None,
    ) -> None:
        """撤销凭证并写审计。"""
        rid = request_id or self.new_request_id()
        tenant = self._tenant_of(credential_id)
        self._credentials.revoke(credential_id, grace_period)
        self._audit.append(
            AuditEntry(
                request_id=rid,
                timestamp=self._clock(),
                tenant=tenant,
                endpoint="admin:revoke_credential",
                decision="credential_revoked",
                rule="credential.revoke",
                detail=(
                    f"撤销凭证 {credential_id}"
                    + (
                        f"，兼容窗口 grace_period={grace_period}s"
                        if grace_period > 0
                        else "，立即生效"
                    )
                ),
                credential_id=credential_id,
            )
        )

    def _tenant_of(self, credential_id: str) -> str:
        record = self._store.get_credential(credential_id)
        return record.tenant if record else ""

    # ---- 授权判定 ---------------------------------------------------

    def authorize(
        self,
        token: str | None,
        endpoint: str,
        required_scope: str,
        request_id: str | None = None,
    ) -> AuthDecision:
        """执行一次完整授权判定，返回放行结论或抛 :class:`GovernanceError`。

        无论放行还是拒绝都写审计（携带 request_id、命中规则与判定依据）。
        租户以凭证内嵌的租户为准，配额按该 (租户, 接口) 维度统计。
        """
        rid = request_id or self.new_request_id()
        with self._store.lock:
            # 1) 认证 + 权限
            try:
                decision = self._credentials.authenticate(token, required_scope)
            except GovernanceError as exc:
                self._deny(
                    rid,
                    tenant="",
                    endpoint=endpoint,
                    exc=exc,
                    quota_used=None,
                    quota_limit=None,
                )
                raise
            tenant = decision.tenant
            # 2) 配额只读评估（拒绝路径绝不计数）
            projected, ok = self._quotas.evaluate(tenant, endpoint)
            if not ok:
                exc = QuotaExceeded(projected, self._clock()).as_governance_error()
                self._deny(
                    rid,
                    tenant=tenant,
                    endpoint=endpoint,
                    exc=exc,
                    quota_used=projected.used,
                    quota_limit=projected.limit,
                )
                raise exc
            # 3) 审计先行（fsync），成功后才提交配额
            entry = AuditEntry(
                request_id=rid,
                timestamp=self._clock(),
                tenant=tenant,
                endpoint=endpoint,
                decision="allow",
                rule="authorize.allow",
                detail=(
                    f"认证通过（{decision.rule}）且配额预占成功："
                    f"{projected.used if projected.limit >= 0 else '不限流'}"
                    + (f"/{projected.limit}" if projected.limit >= 0 else "")
                ),
                credential_id=decision.credential_id,
                quota_used=projected.used if projected.limit >= 0 else None,
                quota_limit=projected.limit if projected.limit >= 0 else None,
            )
            try:
                self._audit.append(entry)
            except AuditError as audit_exc:
                # 未提交配额 -> 无幽灵配额；按审计失败拒绝，绝不静默放行。
                raise GovernanceError(
                    DenyReason.AUDIT_FAILURE,
                    rule="audit.append",
                    detail=f"放行审计写入失败，请求被拒绝：{audit_exc}",
                    request_id=rid,
                ) from audit_exc
            try:
                self._quotas.commit(projected)
            except GovernanceError as commit_exc:
                # 防御性补偿：同 request_id 补记拒绝，结论可解释。
                self._safe_deny(
                    rid,
                    tenant=tenant,
                    endpoint=endpoint,
                    reason=DenyReason.AUDIT_FAILURE,
                    rule="quota.commit",
                    detail=f"配额提交失败，请求被拒绝：{commit_exc.detail}",
                    credential_id=decision.credential_id,
                    quota_used=projected.used,
                    quota_limit=projected.limit,
                )
                raise GovernanceError(
                    DenyReason.AUDIT_FAILURE,
                    rule="quota.commit",
                    detail=f"配额提交失败，请求被拒绝：{commit_exc.detail}",
                    request_id=rid,
                ) from commit_exc
            decision.rule = "authorize.allow"
            decision.detail = entry.detail
            return decision

    # ---- 审计写入辅助 -----------------------------------------------

    def _deny(
        self,
        rid: str,
        tenant: str,
        endpoint: str,
        exc: GovernanceError,
        quota_used: int | None,
        quota_limit: int | None,
    ) -> None:
        """为一次拒绝写审计；审计再失败则升级为 AUDIT_FAILURE 拒绝。"""
        exc.request_id = rid
        try:
            self._audit.append(
                AuditEntry(
                    request_id=rid,
                    timestamp=self._clock(),
                    tenant=tenant,
                    endpoint=endpoint,
                    decision="deny",
                    rule=exc.rule,
                    reason=exc.reason.value,
                    detail=exc.detail,
                    quota_used=quota_used,
                    quota_limit=quota_limit,
                )
            )
        except AuditError as audit_exc:
            raise GovernanceError(
                DenyReason.AUDIT_FAILURE,
                rule="audit.append",
                detail=f"拒绝审计写入失败，请求维持拒绝：{audit_exc}",
                request_id=rid,
            ) from audit_exc

    def _safe_deny(self, **kwargs: object) -> None:
        """补偿性审计；若审计也失败则忽略（原拒绝结论已成立）。"""
        try:
            self._audit.append(
                AuditEntry(
                    decision="deny",
                    timestamp=self._clock(),
                    **kwargs,  # type: ignore[arg-type]
                )
            )
        except AuditError:
            pass
