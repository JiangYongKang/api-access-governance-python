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
