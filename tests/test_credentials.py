"""凭证生命周期与拒绝原因可区分性测试。"""

from __future__ import annotations

import logging

import pytest

from governance.errors import DenyReason, GovernanceError
from governance.persistence import GovernanceStore
from governance.service import GovernanceService
from tests.helpers import MutableClock

logger = logging.getLogger("test.credentials")

ENDPOINT = "GET /tenant/data"
SCOPE = "read:data"


def _authorize(svc: GovernanceService, token: str | None, rid: str):
    try:
        decision = svc.authorize(token, ENDPOINT, SCOPE, request_id=rid)
        logger.info(
            "request_id=%s rule=%s 判定=放行 tenant=%s credential=%s",
            rid, decision.rule, decision.tenant, decision.credential_id,
        )
        return decision
    except GovernanceError as exc:
        logger.warning(
            "request_id=%s rule=%s 判定=拒绝 reason=%s 依据=%s",
            rid, exc.rule, exc.reason.value, exc.detail,
        )
        raise


def test_distinct_deny_reasons(service: GovernanceService) -> None:
    svc = service
    cid, token = svc.issue_credential("t1", {SCOPE}, ttl_seconds=100)
    _cid_no_scope, token_no_scope = svc.issue_credential("t1", {"other"})

    cases = [
        ("missing", None, DenyReason.MISSING_CREDENTIAL, "credential.present"),
        ("format", "garbage", DenyReason.UNTRUSTED_FORMAT, "credential.format"),
        (
            "unknown",
            "lgac_" + "0" * 32 + ".deadbeef",
            DenyReason.UNKNOWN_CREDENTIAL,
            "credential.exists",
        ),
        ("scope", token_no_scope, DenyReason.INSUFFICIENT_SCOPE, "credential.scope"),
    ]
    for label, tok, expected_reason, expected_rule in cases:
        with pytest.raises(GovernanceError) as ei:
            _authorize(svc, tok, f"rid-{label}")
        assert ei.value.reason is expected_reason, label
        assert ei.value.rule == expected_rule, label
        assert ei.value.request_id == f"rid-{label}"

    # 过期：拨时钟超过 ttl
    svc._clock.advance(101)
    with pytest.raises(GovernanceError) as ei:
        _authorize(svc, token, "rid-expired")
    assert ei.value.reason is DenyReason.EXPIRED_CREDENTIAL
    assert ei.value.rule == "credential.expires_at"

    # 已撤销（立即生效）
    svc.revoke_credential(cid, grace_period=0.0, request_id="rid-revoke-op")
    with pytest.raises(GovernanceError) as ei:
        _authorize(svc, token, "rid-revoked")
    assert ei.value.reason is DenyReason.REVOKED_CREDENTIAL
    assert ei.value.rule == "credential.revoked"
    # 凭证变更操作本身可在审计中按请求标识追溯
    rows = svc.audit.query(request_id="rid-revoke-op")
    assert len(rows) == 1 and rows[0].decision == "credential_revoked"


def test_forged_secret_is_untrusted(service: GovernanceService) -> None:
    svc = service
    _, token = svc.issue_credential("t1", {SCOPE})
    forged = token[:-3] + ("AAA" if not token.endswith("AAA") else "BBB")
    with pytest.raises(GovernanceError) as ei:
        _authorize(svc, forged, "rid-forged")
    assert ei.value.reason is DenyReason.UNTRUSTED_FORMAT
    assert ei.value.rule == "credential.secret"


def test_rotation_grace_window(service: GovernanceService, clock: MutableClock) -> None:
    svc = service
    old_id, old_tok = svc.issue_credential("t1", {SCOPE})
    new_id, new_tok = svc.rotate_credential(old_id, grace_period=30, request_id="rot-1")

    # 轮换生效瞬间：在途的旧凭证请求在兼容窗口内仍放行，新凭证也放行
    assert _authorize(svc, old_tok, "inflight-old-1").allowed
    assert _authorize(svc, new_tok, "inflight-new-1").allowed

    # 窗口结束：旧凭证以稳定原因 EXPIRED_CREDENTIAL/grace_window_closed 拒绝
    clock.advance(31)
    with pytest.raises(GovernanceError) as ei:
        _authorize(svc, old_tok, "old-after-grace")
    assert ei.value.reason is DenyReason.EXPIRED_CREDENTIAL
    assert ei.value.rule == "credential.grace_window_closed"
    # 新凭证不受影响
    assert _authorize(svc, new_tok, "new-after-grace").allowed

    rows = svc.audit.query(request_id="rot-1")
    assert rows[0].decision == "credential_rotated"
    assert new_id in rows[0].detail and "30" in rows[0].detail


def test_revoke_with_grace_then_hard_deny(
    service: GovernanceService, clock: MutableClock
) -> None:
    svc = service
    cid, tok = svc.issue_credential("t1", {SCOPE})
    svc.revoke_credential(cid, grace_period=10, request_id="rev-1")
    # 兼容窗口内的在途请求语义确定：继续放行
    assert _authorize(svc, tok, "inflight-revoked-grace").allowed
    clock.advance(11)
    # 窗口后一律按撤销拒绝，原因稳定
    with pytest.raises(GovernanceError) as ei:
        _authorize(svc, tok, "revoked-after-grace")
    assert ei.value.reason is DenyReason.REVOKED_CREDENTIAL
    assert ei.value.rule == "credential.revoked"


def test_revoked_cannot_rotate(service: GovernanceService) -> None:
    svc = service
    cid, _ = svc.issue_credential("t1", {SCOPE})
    svc.revoke_credential(cid)
    with pytest.raises(GovernanceError) as ei:
        svc.rotate_credential(cid, request_id="bad-rotate")
    assert ei.value.reason is DenyReason.REVOKED_CREDENTIAL


def test_state_survives_restart(tmp_path, service: GovernanceService) -> None:
    svc = service
    cid, tok = svc.issue_credential("t1", {SCOPE}, ttl_seconds=100)
    svc.revoke_credential(cid)
    # 用同一文件新建服务模拟重启：撤销结论保持一致
    store = GovernanceStore(tmp_path / "state.json")
    store.load()
    restarted = GovernanceService(store, svc.audit, clock=svc._clock)
    with pytest.raises(GovernanceError) as ei:
        restarted.authorize(tok, ENDPOINT, SCOPE, request_id="after-restart")
    assert ei.value.reason is DenyReason.REVOKED_CREDENTIAL
