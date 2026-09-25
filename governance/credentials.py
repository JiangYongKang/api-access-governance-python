"""凭证签发、轮换、撤销与校验。

Token 格式：``v1.<key_id>.<sig>``，其中 sig = HMAC-SHA256(secret, key_id) 的前 32 位十六进制。
无法解析为该格式、key_id 未知或签名不匹配的 token 一律视为不可信并拒绝。

轮换语义（在途请求确定性）：
- rotate 签发同租户、同权限范围的新凭证；旧凭证进入兼容窗口（grace），
  在 ``min(expires_at, grace_until)`` 之前旧 token 仍被接受，窗口结束后按过期拒绝。
- revoke 立即生效并终止兼容窗口：已撤销凭证一律拒绝，无论是否在窗口内。
- 判定发生在请求入口；已放行的在途请求不受后续轮换/撤销影响。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from .errors import DecisionReason
from .models import Credential
from .storage import Storage

# 轮换兼容窗口（秒）：旧凭证在窗口内仍被接受，在途请求语义确定
DEFAULT_GRACE_SECONDS = 30.0

_TOKEN_VERSION = "v1"
_SIG_LEN = 32


def _sign(secret: str, key_id: str) -> str:
    return hmac.new(secret.encode(), key_id.encode(), hashlib.sha256).hexdigest()[:_SIG_LEN]


class CredentialManager:
    def __init__(self, storage: Storage, grace_seconds: float = DEFAULT_GRACE_SECONDS) -> None:
        self._storage = storage
        self._grace = grace_seconds

    def issue(self, tenant_id: str, scopes: set[str], ttl_seconds: float, now: float) -> tuple[str, Credential]:
        """签发凭证，返回 (token, 凭证记录)。"""
        key_id = secrets.token_hex(8)
        cred = Credential(
            key_id=key_id, tenant_id=tenant_id, scopes=frozenset(scopes),
            secret=secrets.token_hex(16), issued_at=now, expires_at=now + ttl_seconds,
        )
        self._storage.save_credential(cred)
        return self._encode(cred), cred

    def rotate(self, key_id: str, now: float) -> tuple[str, Credential]:
        """轮换：签发同租户同权限的新凭证，旧凭证进入兼容窗口。"""
        old = self._storage.get_credential(key_id)
        if old is None:
            raise KeyError(f"unknown credential: {key_id}")
        token, new_cred = self.issue(old.tenant_id, set(old.scopes),
                                     ttl_seconds=old.expires_at - now, now=now)
        self._storage.save_credential(Credential(
            key_id=old.key_id, tenant_id=old.tenant_id, scopes=old.scopes,
            secret=old.secret, issued_at=old.issued_at, expires_at=old.expires_at,
            revoked=old.revoked, grace_until=now + self._grace,
        ))
        return token, new_cred

    def revoke(self, key_id: str, now: float) -> None:
        """撤销：立即生效，兼容窗口同时终止。"""
        old = self._storage.get_credential(key_id)
        if old is None:
            raise KeyError(f"unknown credential: {key_id}")
        self._storage.save_credential(Credential(
            key_id=old.key_id, tenant_id=old.tenant_id, scopes=old.scopes,
            secret=old.secret, issued_at=old.issued_at, expires_at=old.expires_at,
            revoked=True, grace_until=0.0,
        ))

    def resolve(self, token: str, now: float) -> tuple[Credential | None, DecisionReason]:
        """解析 token。返回 (凭证或 None, 判定原因)。"""
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != _TOKEN_VERSION or not parts[1] or not parts[2]:
            return None, DecisionReason.MALFORMED_CREDENTIAL
        _, key_id, sig = parts
        cred = self._storage.get_credential(key_id)
        if cred is None or not hmac.compare_digest(sig, _sign(cred.secret, key_id)):
            return None, DecisionReason.UNKNOWN_CREDENTIAL
        if cred.revoked:
            return None, DecisionReason.CREDENTIAL_REVOKED
        if now >= cred.expires_at:
            return None, DecisionReason.CREDENTIAL_EXPIRED
        if cred.grace_until > 0 and now >= cred.grace_until:
            # 轮换兼容窗口已结束，旧凭证不再被接受
            return None, DecisionReason.CREDENTIAL_EXPIRED
        return cred, DecisionReason.ALLOWED

    @staticmethod
    def _encode(cred: Credential) -> str:
        return f"{_TOKEN_VERSION}.{cred.key_id}.{_sign(cred.secret, cred.key_id)}"
