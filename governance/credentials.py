"""凭证生命周期管理：签发、轮换、撤销与认证判定。

语义约定（详见 README）:
- 轮换(rotate)：生成新版本凭证（新 id、新随机秘密），旧凭证记录保留
  并设置 ``grace_until = now + grace_period``；兼容窗口内旧凭证仍可
  认证，窗口结束后按"已过期的兼容窗口"拒绝（reason=EXPIRED_CREDENTIAL，
  rule=credential.grace_window_closed）。
- 撤销(revoke)：设置 ``revoked_at``。``grace_period=0``（默认）立即
  拒绝在途及之后到达的旧凭证请求（reason=REVOKED_CREDENTIAL）；
  ``grace_period>0`` 时旧凭证在窗口内仍可用，窗口结束按撤销拒绝。
- 已经进入服务端临界区（authenticate 已开始）的在途请求，其结论基于
  该临界区内读到的快照，因此判定结果确定可复现。
- 所有方法在 :class:`~governance.persistence.GovernanceStore` 的同一把
  锁内执行，保证认证结论与状态变更互斥。
"""

from __future__ import annotations

import time
from collections.abc import Callable

from governance import tokens
from governance.errors import DenyReason, GovernanceError
from governance.model import AuthDecision, CredentialRecord
from governance.persistence import GovernanceStore


class CredentialService:
    """凭证签发/轮换/撤销/认证。"""

    def __init__(
        self,
        store: GovernanceStore,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._store = store
        self._clock = clock or time.time

    def _now(self) -> float:
        return self._clock()

    def issue(
        self,
        tenant: str,
        scopes: set[str] | frozenset[str],
        ttl_seconds: float | None = None,
    ) -> tuple[str, str]:
        """签发凭证，返回 (credential_id, 明文 token)。"""
        if not tenant:
            raise GovernanceError(
                DenyReason.UNTRUSTED_FORMAT,
                rule="credential.issue",
                detail="tenant 不能为空",
            )
        scope_set = frozenset(scopes)
        now = self._now()
        credential_id = tokens.generate_credential_id()
        plaintext = tokens.generate_token(credential_id)
        record = CredentialRecord(
            credential_id=credential_id,
            tenant=tenant,
            scopes=scope_set,
            token_hash=tokens.hash_token(plaintext),
            version=1,
            issued_at=now,
            expires_at=None if ttl_seconds is None else now + ttl_seconds,
        )
        with self._store.lock:
            self._store.put_credential(record)
            self._store.persist()
        return credential_id, plaintext

    def rotate(
        self,
        credential_id: str,
        grace_period: float = 0.0,
    ) -> tuple[str, str]:
        """轮换凭证，返回新的 (credential_id, 明文 token)。

        旧凭证保留、版本号沿用其记录并设置
        ``grace_until = now + grace_period``，并指向新凭证 id。
        """
        if grace_period < 0:
            raise GovernanceError(
                DenyReason.UNTRUSTED_FORMAT,
                rule="credential.rotate",
                detail="grace_period 不能为负数",
            )
        with self._store.lock:
            old = self._store.get_credential(credential_id)
            if old is None:
                raise GovernanceError(
                    DenyReason.UNKNOWN_CREDENTIAL,
                    rule="credential.rotate",
                    detail=f"凭证 {credential_id} 不存在，无法轮换",
                )
            now = self._now()
            if old.is_revoked:
                raise GovernanceError(
                    DenyReason.REVOKED_CREDENTIAL,
                    rule="credential.rotate",
                    detail=f"凭证 {credential_id} 已撤销，不能轮换",
                )
            new_id = tokens.generate_credential_id()
            plaintext = tokens.generate_token(new_id)
            new_record = CredentialRecord(
                credential_id=new_id,
                tenant=old.tenant,
                scopes=old.scopes,
                token_hash=tokens.hash_token(plaintext),
                version=old.version + 1,
                issued_at=now,
                expires_at=old.expires_at,
            )
            old.superseded_by = new_id
            old.grace_until = now + grace_period
            self._store.put_credential(old)
            self._store.put_credential(new_record)
            self._store.persist()
        return new_id, plaintext

    def revoke(self, credential_id: str, grace_period: float = 0.0) -> None:
        """撤销凭证；``grace_period`` 兼容窗口语义见模块文档。"""
        if grace_period < 0:
            raise GovernanceError(
                DenyReason.UNTRUSTED_FORMAT,
                rule="credential.revoke",
                detail="grace_period 不能为负数",
            )
        with self._store.lock:
            record = self._store.get_credential(credential_id)
            if record is None:
                raise GovernanceError(
                    DenyReason.UNKNOWN_CREDENTIAL,
                    rule="credential.revoke",
                    detail=f"凭证 {credential_id} 不存在，无法撤销",
                )
            now = self._now()
            record.revoked_at = now
            record.grace_until = now + grace_period
            self._store.put_credential(record)
            self._store.persist()

    def authenticate(
        self,
        token: str | None,
        required_scope: str,
    ) -> AuthDecision:
        """认证并检查权限范围。

        判定顺序（先命中先生效，保证原因可区分）:
        缺失 -> 格式不可信 -> 不存在 -> 已撤销（兼容窗口外）->
        已过期 -> 轮换兼容窗口结束 -> 秘密不匹配 -> 权限不足 -> 通过。
        调用方应持有 store 锁；这里自行加锁以保证语义独立可用。
        """
        now = self._now()
        if token is None or not token:
            raise GovernanceError(
                DenyReason.MISSING_CREDENTIAL,
                rule="credential.present",
                detail="请求未携带凭证",
            )
        credential_id = tokens.parse_token(token)
        with self._store.lock:
            record = self._store.get_credential(credential_id)
            if record is None:
                raise GovernanceError(
                    DenyReason.UNKNOWN_CREDENTIAL,
                    rule="credential.exists",
                    detail=f"凭证 id {credential_id} 在服务端无记录",
                )
            # 撤销判定优先，但兼容窗口内的在途旧凭证仍放行。
            if record.is_revoked and not record.in_grace(now):
                raise GovernanceError(
                    DenyReason.REVOKED_CREDENTIAL,
                    rule="credential.revoked",
                    detail=(
                        f"凭证已于 {record.revoked_at} 撤销"
                        + (
                            f"，兼容窗口截止 {record.grace_until}"
                            if record.grace_until is not None
                            else ""
                        )
                    ),
                )
            # 自身有效期。
            if record.is_expired(now):
                raise GovernanceError(
                    DenyReason.EXPIRED_CREDENTIAL,
                    rule="credential.expires_at",
                    detail=f"凭证已于 {record.expires_at} 过期（当前 {now}）",
                )
            # 轮换/撤销遗留的兼容窗口关闭（未撤销但 grace 已结束）。
            if record.grace_until is not None and not record.in_grace(now):
                if record.is_revoked:
                    # 理论上前面的撤销分支已覆盖，保留为显式防御。
                    raise GovernanceError(
                        DenyReason.REVOKED_CREDENTIAL,
                        rule="credential.revoked",
                        detail=f"凭证已撤销且兼容窗口于 {record.grace_until} 结束",
                    )
                raise GovernanceError(
                    DenyReason.EXPIRED_CREDENTIAL,
                    rule="credential.grace_window_closed",
                    detail=f"旧凭证兼容窗口已于 {record.grace_until} 结束，请使用新版本",
                )
            # 秘密比对（常量时间）。
            if not tokens.constant_time_equals(record.token_hash, tokens.hash_token(token)):
                raise GovernanceError(
                    DenyReason.UNTRUSTED_FORMAT,
                    rule="credential.secret",
                    detail="凭证秘密与签发记录不一致（疑似伪造或截断）",
                )
            if required_scope not in record.scopes:
                raise GovernanceError(
                    DenyReason.INSUFFICIENT_SCOPE,
                    rule="credential.scope",
                    detail=(
                        f"凭证权限 {sorted(record.scopes)} 不含所需权限 "
                        f"{required_scope!r}"
                    ),
                )
            return AuthDecision(
                allowed=True,
                credential_id=record.credential_id,
                tenant=record.tenant,
                scopes=record.scopes,
                rule="credential.ok",
                detail="凭证有效且权限范围满足",
            )
