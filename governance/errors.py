"""可区分的拒绝原因与治理异常分类。

所有拒绝都使用 :class:`GovernanceError` 抛出，``reason`` 取
:class:`DenyReason` 中的稳定枚举值，``rule`` 为命中的规则标识，
``detail`` 为人类可读的判定依据。
"""

from __future__ import annotations

from enum import Enum


class DenyReason(str, Enum):
    """稳定的拒绝原因枚举（字符串值即对外错误码，不随版本变更）。"""

    MISSING_CREDENTIAL = "missing_credential"
    UNTRUSTED_FORMAT = "untrusted_format"
    UNKNOWN_CREDENTIAL = "unknown_credential"
    REVOKED_CREDENTIAL = "revoked_credential"
    EXPIRED_CREDENTIAL = "expired_credential"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    QUOTA_EXCEEDED = "quota_exceeded"
    AUDIT_FAILURE = "audit_failure"


class GovernanceError(Exception):
    """携带结构化判定依据的拒绝异常。

    属性:
        reason: 稳定错误码（:class:`DenyReason`）。
        rule: 命中的规则标识，如 ``credential.revoked``。
        detail: 判定依据的文字说明。
        request_id: 关联的请求标识（可选）。
    """

    def __init__(
        self,
        reason: DenyReason,
        rule: str,
        detail: str,
        request_id: str | None = None,
    ) -> None:
        self.reason = reason
        self.rule = rule
        self.detail = detail
        self.request_id = request_id
        super().__init__(f"[{reason.value}] {rule}: {detail}")


class StorageError(Exception):
    """本地持久化层异常。"""


class AuditError(Exception):
    """审计流水写入/查询异常。"""
