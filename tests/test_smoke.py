"""冒烟测试骨架：确认所有模块可导入、骨架可运行。"""

from __future__ import annotations

from governance import (  # noqa: F401
    AuditLog,
    CredentialService,
    DenyReason,
    GovernanceError,
    GovernanceService,
    GovernanceStore,
    QuotaManager,
    model,
    tokens,
)


def test_imports() -> None:
    assert DenyReason.QUOTA_EXCEEDED.value == "quota_exceeded"
    assert {AuditLog, CredentialService, GovernanceService, GovernanceStore, QuotaManager}


def test_error_classification() -> None:
    err = GovernanceError(
        DenyReason.REVOKED_CREDENTIAL,
        rule="credential.revoked",
        detail="revoked at 0",
        request_id="req-1",
    )
    assert err.reason is DenyReason.REVOKED_CREDENTIAL
    assert err.rule == "credential.revoked"
    assert err.request_id == "req-1"
