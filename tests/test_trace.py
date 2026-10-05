"""判定追溯：放行/拒绝都能按 request_id 查到命中的策略、当时用量与上限；
策略或记账链路异常时一律拒绝，绝不静默放行。"""

from governance.errors import DecisionReason as R
from governance.errors import PolicyStoreError

from .conftest import ENDPOINT, log_decision


def test_allowed_request_is_traceable_with_snapshot(stack):
    """放行请求也有判定记录，且含命中策略、两层用量与上限。"""
    svc, _ = stack
    svc._quota.set_policy("t1", ENDPOINT, total_limit=5,
                          window_seconds=10.0, window_limit=3)
    token = svc.issue_credential("t1", {"read"}, 1000.0, "req-issue", now=0.0)

    d = svc.authorize(token, ENDPOINT, "req-allow-trace", now=1.0)
    assert d.allowed
    snap = svc._quota.get_decision("req-allow-trace")
    assert snap is not None
    assert snap["allowed"] is True
    assert snap["reason"] == "allowed"
    assert snap["tenant_id"] == "t1" and snap["endpoint"] == ENDPOINT
    assert snap["total_used"] == 1 and snap["total_limit"] == 5
    assert snap["window_used"] == 1 and snap["window_limit"] == 3
    assert snap["window_seconds"] == 10.0 and snap["policy_source"] == "tenant"
    # 放行也进审计流水
    allowed_records = svc._audit.query(event="access_allowed")
    assert any(r.request_id == "req-allow-trace" for r in allowed_records)


def test_denied_request_trace_reports_limiting_layer(stack):
    svc, _ = stack
    svc._quota.set_policy("t1", ENDPOINT, total_limit=None,
                          window_seconds=10.0, window_limit=1)
    token = svc.issue_credential("t1", {"read"}, 1000.0, "req-issue", now=0.0)
    svc.authorize(token, ENDPOINT, "d1", now=1.0)
    d = svc.authorize(token, ENDPOINT, "d2", now=1.0)
    log_decision("trace-deny", "d2", d)
    assert not d.allowed and d.reason is R.RATE_LIMITED
    snap = svc._quota.get_decision("d2")
    assert snap["allowed"] is False and snap["layer"] == "window"
    assert snap["reason"] == "rate_limited"
    assert "window limit reached" in snap["detail"]


def test_every_decision_is_queryable_by_request_id(stack):
    """每一笔判定（含凭证类拒绝）都可按请求标识查到。"""
    svc, _ = stack
    token = svc.issue_credential("t1", {"read"}, 1000.0, "req-issue", now=0.0)
    svc.authorize(token, ENDPOINT, "ok-1", now=1.0)
    svc.authorize("garbage", ENDPOINT, "bad-1", now=1.0)
    svc.authorize("v1.unknown.0123456789abcdef0123456789abcdef",
                  ENDPOINT, "bad-2", now=1.0)
    assert svc._quota.get_decision("ok-1")["allowed"] is True
    bad1 = svc._quota.get_decision("bad-1")
    bad2 = svc._quota.get_decision("bad-2")
    assert bad1["allowed"] is False and bad1["reason"] == "malformed_credential"
    assert bad2["allowed"] is False and bad2["reason"] == "unknown_credential"
    assert svc._quota.get_decision("missing-id") is None


def test_policy_store_failure_denies_request(stack, monkeypatch):
    """策略读取链路异常：请求必须被拒绝（POLICY_FAILURE），不得放行。"""
    svc, _ = stack
    token = svc.issue_credential("t1", {"read"}, 1000.0, "req-issue", now=0.0)

    def boom(*_a, **_k):
        raise PolicyStoreError("simulated policy store outage")

    monkeypatch.setattr(svc._quota, "acquire", boom)
    d = svc.authorize(token, ENDPOINT, "req-policy-fail", now=1.0)
    log_decision("policy-failure", "req-policy-fail", d)
    assert not d.allowed and d.reason is R.POLICY_FAILURE
    assert "denied" in d.detail
    assert svc._quota.usage("t1", ENDPOINT) == 0  # 异常路径不吃计数


def test_storage_outage_denies_request(stack):
    """记账/追溯存储整体不可用（如已关闭）：fail-closed。"""
    svc, storage = stack
    token = svc.issue_credential("t1", {"read"}, 1000.0, "req-issue", now=0.0)
    storage.close()
    d = svc.authorize(token, ENDPOINT, "req-storage-down", now=1.0)
    log_decision("storage-down", "req-storage-down", d)
    assert not d.allowed
    assert d.reason in (R.POLICY_FAILURE, R.AUDIT_FAILURE)
