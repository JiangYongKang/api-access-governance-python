"""治理域的数据类型定义（凭证、判定结论、审计条目）。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CredentialRecord:
    """一条本地凭证的服务端记录（只存哈希，不存明文）。"""

    credential_id: str
    tenant: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    token_hash: str = ""
    version: int = 1
    issued_at: float = 0.0
    expires_at: float | None = None
    revoked_at: float | None = None
    # 轮换/撤销的兼容窗口截止时间：旧凭证在此之前仍被接受。
    grace_until: float | None = None
    # 轮换后指向新版本凭证 id；撤销后为 None。
    superseded_by: str | None = None

    @property
    def is_revoked(self) -> bool:
        """是否已被撤销（revoked_at 被置位即视为撤销动作生效）。"""
        return self.revoked_at is not None

    def is_expired(self, now: float) -> bool:
        """是否超过有效期截止时间；无 expires_at 表示长期有效。"""
        return self.expires_at is not None and now >= self.expires_at

    def in_grace(self, now: float) -> bool:
        """旧凭证是否处于轮换/撤销兼容窗口内（now < grace_until）。"""
        return self.grace_until is not None and now < self.grace_until


@dataclass
class AuthDecision:
    """认证与授权判定结论。"""

    allowed: bool
    credential_id: str
    tenant: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    rule: str = ""
    detail: str = ""


@dataclass
class AuditEntry:
    """一条审计流水。"""

    request_id: str
    timestamp: float
    tenant: str
    endpoint: str
    decision: str  # allow / deny / credential_issued / credential_rotated / credential_revoked
    rule: str = ""
    reason: str = ""
    detail: str = ""
    credential_id: str = ""
    quota_used: int | None = None
    quota_limit: int | None = None


@dataclass
class QuotaState:
    """单个 (租户, 接口) 维度的配额状态。"""

    tenant: str
    endpoint: str
    limit: int
    window_seconds: float = 60.0
    used: int = 0
    window_start: float = 0.0
