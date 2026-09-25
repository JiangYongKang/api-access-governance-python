"""凭证边界场景：格式、过期、撤销、权限不足，以及轮换/撤销期间的在途请求语义。"""

from governance.errors import DecisionReason as R

from .conftest import ENDPOINT, GRACE, log_decision


def test_malformed_and_unknown_credentials_are_distinguishable(stack):
    svc, _ = stack
    d1 = svc.authorize("not-a-token", ENDPOINT, "req-malformed", now=0.0)
    d2 = svc.authorize("v1.nosuchkey.0123456789abcdef0123456789abcdef", ENDPOINT,
                       "req-unknown", now=0.0)
    log_decision("malformed", "req-malformed", d1)
    log_decision("unknown", "req-unknown", d2)
    assert not d1.allowed and d1.reason is R.MALFORMED_CREDENTIAL
    assert not d2.allowed and d2.reason is R.UNKNOWN_CREDENTIAL
    assert d1.reason is not d2.reason  # 失败原因可区分


def test_expired_credential_rejected(stack):
    svc, _ = stack
    token = svc.issue_credential("t1", {"read"}, ttl_seconds=100.0,
                                 request_id="req-issue", now=0.0)
    d = svc.authorize(token, ENDPOINT, "req-expired", now=100.0)
    log_decision("expired", "req-expired", d)
    assert not d.allowed and d.reason is R.CREDENTIAL_EXPIRED


def test_insufficient_scope_rejected_and_not_counted(stack):
    svc, _ = stack
    token = svc.issue_credential("t1", {"write"}, ttl_seconds=100.0,
                                 request_id="req-issue", now=0.0)
    d = svc.authorize(token, ENDPOINT, "req-scope", now=1.0)
    log_decision("scope", "req-scope", d)
    assert not d.allowed and d.reason is R.INSUFFICIENT_SCOPE
    assert svc._quota.usage("t1", ENDPOINT) == 0  # 未放行不计配额


def test_revoked_credential_rejected_immediately(stack):
    svc, storage = stack
    token = svc.issue_credential("t1", {"read"}, ttl_seconds=100.0,
                                 request_id="req-issue", now=0.0)
    key_id = token.split(".")[1]
    svc.revoke_credential(key_id, "t1", "req-revoke", now=1.0)
    d = svc.authorize(token, ENDPOINT, "req-after-revoke", now=2.0)
    log_decision("revoked", "req-after-revoke", d)
    assert not d.allowed and d.reason is R.CREDENTIAL_REVOKED


def test_rotation_grace_window_semantics(stack):
    """轮换：旧凭证在兼容窗口内仍被接受（在途请求确定放行），窗口结束后按过期拒绝。"""
    svc, _ = stack
    old_token = svc.issue_credential("t1", {"read"}, ttl_seconds=1000.0,
                                     request_id="req-issue", now=0.0)
    old_key = old_token.split(".")[1]
    new_token = svc.rotate_credential(old_key, "req-rotate", now=100.0)

    # 窗口内：旧 token 仍放行（模拟轮换前已发出的在途请求）
    d_in = svc.authorize(old_token, ENDPOINT, "req-inflight-old", now=100.0 + GRACE - 1)
    log_decision("grace-inside", "req-inflight-old", d_in)
    assert d_in.allowed

    # 窗口结束后：旧 token 拒绝，新 token 放行
    d_out = svc.authorize(old_token, ENDPOINT, "req-after-grace", now=100.0 + GRACE)
    d_new = svc.authorize(new_token, ENDPOINT, "req-new-token", now=100.0 + GRACE)
    log_decision("grace-elapsed", "req-after-grace", d_out)
    log_decision("new-token", "req-new-token", d_new)
    assert not d_out.allowed and d_out.reason is R.CREDENTIAL_EXPIRED
    assert d_new.allowed


def test_revoke_during_grace_terminates_old_token(stack):
    """兼容窗口内执行撤销：撤销立即生效，旧 token 不再被接受。"""
    svc, _ = stack
    old_token = svc.issue_credential("t1", {"read"}, ttl_seconds=1000.0,
                                     request_id="req-issue", now=0.0)
    old_key = old_token.split(".")[1]
    svc.rotate_credential(old_key, "req-rotate", now=100.0)
    svc.revoke_credential(old_key, "t1", "req-revoke", now=101.0)  # 窗口内撤销
    d = svc.authorize(old_token, ENDPOINT, "req-revoked-in-grace", now=102.0)
    log_decision("revoked-in-grace", "req-revoked-in-grace", d)
    assert not d.allowed and d.reason is R.CREDENTIAL_REVOKED
