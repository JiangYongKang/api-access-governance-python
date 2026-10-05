"""核心数据模型：凭证、判定结果、审计记录。"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import DecisionReason


@dataclass(frozen=True)
class Credential:
    """一份已签发的本地凭证（存储侧视图）。"""

    key_id: str
    tenant_id: str
    scopes: frozenset[str]
    secret: str
    issued_at: float
    expires_at: float
    revoked: bool = False
    # 轮换兼容窗口：旧凭证被替换后仍被接受的截止时间（仅用于轮换语义）
    grace_until: float = 0.0


@dataclass(frozen=True)
class Policy:
    """一条配额策略（按 tenant_id × endpoint 维度）。

    - total_limit：累计总量上限（None 表示该层不限制）。
    - window_seconds / window_limit：滚动窗口长度（秒）与窗口内最大次数
      （window_limit 为 None 表示窗口层不限制）。
    - tenant_id == PolicyStore.DEFAULT_TENANT（"*"）表示默认策略，
      对所有没有单独策略的租户生效。
    """

    tenant_id: str
    endpoint: str
    total_limit: int | None
    window_seconds: float
    window_limit: int | None
    updated_at: float = 0.0


@dataclass(frozen=True)
class EffectiveLimits:
    """当前真正生效的两层上限（None 表示该层不限制）。"""

    total_limit: int | None
    window_seconds: float
    window_limit: int | None
    source: str = "none"  # tenant / default / none


@dataclass(frozen=True)
class AcquireResult:
    """一次配额判定（总量层 + 滚动窗口层）的完整结论。"""

    allowed: bool
    layer: str            # ""（放行）/ total / window
    reason: str           # allowed / quota_exceeded / rate_limited
    detail: str
    total_used: int
    total_limit: int | None
    window_used: int
    window_seconds: float
    window_limit: int | None
    policy_source: str    # tenant / default / none


@dataclass(frozen=True)
class Decision:
    """一次授权判定的完整结论，含可解释的判定依据。"""

    allowed: bool
    reason: DecisionReason
    request_id: str
    tenant_id: str | None = None
    detail: str = ""
    # 判定快照：命中的策略来源、当时两层用量与上限（供追溯）
    total_used: int | None = None
    total_limit: int | None = None
    window_used: int | None = None
    window_limit: int | None = None
    window_seconds: float | None = None
    policy_source: str | None = None
    limiting_layer: str | None = None


@dataclass(frozen=True)
class AuditRecord:
    """一条审计流水。"""

    seq: int
    ts: float
    event: str            # access_denied / credential_issued / credential_rotated / credential_revoked
    request_id: str
    tenant_id: str
    reason: str
    detail: str
    extra: dict = field(default_factory=dict)
