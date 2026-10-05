"""判定原因与错误分类定义。"""

from __future__ import annotations

import enum


class DecisionReason(enum.Enum):
    """一次访问判定的结论原因。拒绝原因之间必须可区分。"""

    ALLOWED = "allowed"
    MALFORMED_CREDENTIAL = "malformed_credential"      # 格式不可信
    UNKNOWN_CREDENTIAL = "unknown_credential"          # 签名/标识无法对应已签发凭证
    CREDENTIAL_REVOKED = "credential_revoked"          # 已撤销
    CREDENTIAL_EXPIRED = "credential_expired"          # 已过期
    INSUFFICIENT_SCOPE = "insufficient_scope"          # 权限范围不足
    QUOTA_EXCEEDED = "quota_exceeded"                  # 超出总量配额
    RATE_LIMITED = "rate_limited"                      # 超出滚动时间窗口限制
    POLICY_FAILURE = "policy_failure"                  # 策略/记账链路异常，不放行
    AUDIT_FAILURE = "audit_failure"                    # 审计写入失败，不放行


class GovernanceError(Exception):
    """治理层内部异常基类。"""


class AuditWriteError(GovernanceError):
    """审计流水写入失败。授权链路必须将其视为拒绝，不得静默放行。"""


class PolicyStoreError(GovernanceError):
    """策略读取或配额记账链路异常。授权链路必须将其视为拒绝，不得静默放行。"""
