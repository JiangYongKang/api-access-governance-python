"""核心数据模型：凭证、判定结果、审计记录。"""

from __future__ import annotations

import dataclasses
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
class Decision:
    """一次授权判定的完整结论，含可解释的判定依据。"""

    allowed: bool
    reason: DecisionReason
    request_id: str
    tenant_id: str | None = None
    detail: str = ""
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class QuotaPolicy:
    """一条可持久化的配额策略（租户 × 接口维度）。

    - ``tenant_id == "*"`` 表示默认策略：对该 endpoint 下没有精确策略的租户生效。
    - ``total_limit``：生命周期总量上限；None 表示该层不限。
    - ``window_limit`` / ``window_seconds``：滚动时间窗口“每 window_seconds 秒
      最多 window_limit 次”；两者同时为 None/0 表示该层不限。
    """

    tenant_id: str
    endpoint: str
    total_limit: int | None
    window_limit: int | None
    window_seconds: float | None
    updated_at: float = 0.0

    @property
    def is_default(self) -> bool:
        return self.tenant_id == "*"

    def has_window(self) -> bool:
        return self.window_limit is not None and (self.window_seconds or 0) > 0


@dataclass(frozen=True)
class QuotaSnapshot:
    """一次配额判定时命中的策略层、用量与上限（用于审计追溯与接口查询）。"""

    total_limit: int | None
    total_used: int
    window_limit: int | None
    window_seconds: float | None
    window_used: int
    policy_source: str  # exact / default / none


@dataclass(frozen=True)
class QuotaAcquireResult:
    """一次“检查 + 扣减 + 留痕”的原子配额判定结论。"""

    allowed: bool
    layer: str  # ""（放行）/ total / window / unavailable
    policy: QuotaPolicy | None
    snapshot: QuotaSnapshot
    policy_source: str  # exact / default / none


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
