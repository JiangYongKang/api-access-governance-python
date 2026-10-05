"""持久化配额策略：默认策略对未配置租户生效、重启不丢、反复覆盖结果确定。"""

import pytest

from governance.errors import DecisionReason as R
from governance.storage import DEFAULT_TENANT, Storage

from .conftest import ENDPOINT, log_decision, make_service


def test_default_policy_applies_to_unconfigured_tenant(stack):
    """没有专属策略的租户必须受默认策略约束，不能变成完全不限。"""
    svc, _ = stack
    svc._quota.set_policy(DEFAULT_TENANT, ENDPOINT, total_limit=2)
    token = svc.issue_credential("brand-new-tenant", {"read"}, 1000.0,
                                 "req-issue", now=0.0)

    d1 = svc.authorize(token, ENDPOINT, "req-default-1", now=1.0)
    d2 = svc.authorize(token, ENDPOINT, "req-default-2", now=1.0)
    d3 = svc.authorize(token, ENDPOINT, "req-default-3", now=1.0)
    log_decision("default-policy", "req-default-3", d3)
    assert d1.allowed and d2.allowed
    assert not d3.allowed and d3.reason is R.QUOTA_EXCEEDED
    assert d3.policy_source == "default"  # 命中来源可追溯

    status = svc._quota.status("brand-new-tenant", ENDPOINT, now=1.0)
    assert status["policy_source"] == "default"
    assert status["total_limit"] == 2 and status["total_used"] == 2


def test_tenant_policy_overrides_default_entirely(stack):
    """专属策略整条覆盖默认策略（不合并）。"""
    svc, _ = stack
    svc._quota.set_policy(DEFAULT_TENANT, ENDPOINT, total_limit=2,
                          window_seconds=10.0, window_limit=1)
    svc._quota.set_policy("t9", ENDPOINT, total_limit=5)
    eff = svc._quota.effective_limits("t9", ENDPOINT)
    assert eff.source == "tenant"
    assert eff.total_limit == 5 and eff.window_limit is None


def test_policies_and_usage_survive_restart(tmp_path):
    """策略落盘后重启：不重新下发也按同一套策略判定，用量同样保留。"""
    db = str(tmp_path / "gov.db")
    s1 = Storage(db)
    svc1 = make_service(s1)
    svc1._quota.set_policy(DEFAULT_TENANT, ENDPOINT, total_limit=3)
    svc1._quota.set_policy("tA", ENDPOINT, total_limit=100,
                           window_seconds=10.0, window_limit=2)
    token = svc1.issue_credential("tA", {"read"}, 1000.0, "req-issue", now=0.0)
    assert svc1.authorize(token, ENDPOINT, "req-before-1", now=1.0).allowed
    assert svc1.authorize(token, ENDPOINT, "req-before-2", now=1.0).allowed
    denied = svc1.authorize(token, ENDPOINT, "req-before-3", now=1.0)
    assert not denied.allowed and denied.reason is R.RATE_LIMITED
    s1.close()

    # 重启：同一文件重建栈，不重新下发任何策略
    s2 = Storage(db)
    svc2 = make_service(s2)
    eff = svc2._quota.effective_limits("tA", ENDPOINT)
    assert eff.source == "tenant" and eff.total_limit == 100
    assert eff.window_seconds == 10.0 and eff.window_limit == 2
    assert svc2._quota.usage("tA", ENDPOINT) == 2  # 已用量保留
    # 默认策略也还在，并约束其它租户
    assert svc2._quota.effective_limits("other", ENDPOINT).source == "default"

    # 窗口随时间自然滚动后恢复放行，无需任何手工干预
    d = svc2.authorize(token, ENDPOINT, "req-after-restart", now=12.0)
    log_decision("after-restart", "req-after-restart", d)
    assert d.allowed
    s2.close()


def test_repeated_upsert_is_deterministic_override(stack):
    """同一策略反复下发/上调/下调：以最后一次为准，老策略不残留。"""
    svc, storage = stack
    q = svc._quota
    q.set_policy("t1", ENDPOINT, total_limit=10, window_seconds=5.0, window_limit=3)
    q.set_policy("t1", ENDPOINT, total_limit=20)  # 上调总量，同时清掉窗口层
    eff = q.effective_limits("t1", ENDPOINT)
    assert eff.total_limit == 20 and eff.window_limit is None
    q.set_limit("t1", ENDPOINT, 7)  # 下调（旧接口），窗口配置应保持为空
    eff = q.effective_limits("t1", ENDPOINT)
    assert eff.total_limit == 7 and eff.window_limit is None

    stored = [p for p in storage.list_policies(ENDPOINT) if p.tenant_id == "t1"]
    assert len(stored) == 1  # 只有一条，不存在被调掉的老策略
    assert stored[0].total_limit == 7


def test_set_window_limit_preserves_total(stack):
    """单独调窗口不影响已配置的总量上限。"""
    svc, _ = stack
    svc._quota.set_limit("t1", ENDPOINT, 50)
    svc._quota.set_window_limit("t1", ENDPOINT, window_seconds=8.0, window_limit=4)
    eff = svc._quota.effective_limits("t1", ENDPOINT)
    assert eff.total_limit == 50 and eff.window_limit == 4 and eff.window_seconds == 8.0


def test_invalid_window_config_rejected(stack):
    svc, _ = stack
    with pytest.raises(ValueError):
        svc._quota.set_policy("t1", ENDPOINT, total_limit=5,
                              window_seconds=0.0, window_limit=2)
    with pytest.raises(ValueError):
        svc._quota.set_policy("t1", ENDPOINT, total_limit=-1)
