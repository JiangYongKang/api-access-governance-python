"""持久化配额策略、默认策略、滚动窗口、并发竞争、追溯与 fail-closed。"""

import sqlite3
import threading

import pytest

from governance.audit import AuditLog
from governance.credentials import CredentialManager
from governance.errors import DecisionReason as R
from governance.errors import QuotaError
from governance.models import QuotaPolicy
from governance.quota import QuotaLimiter
from governance.service import GovernanceService
from governance.storage import Storage

from .conftest import ENDPOINT, log_decision


def _make_stack(storage):
    return GovernanceService(
        credentials=CredentialManager(storage),
        quota=QuotaLimiter(storage),
        audit=AuditLog(storage),
        endpoint_scopes={ENDPOINT: "read"},
    )


# ---- 1. 默认策略真正对未单独配置的租户生效 ----
def test_default_policy_applies_to_tenant_without_explicit_policy():
    storage = Storage(":memory:")
    svc = _make_stack(storage)
    # 默认策略：总量 4，窗口 100s 内 2 次
    svc.set_quota_policy(QuotaPolicy("*", ENDPOINT, total_limit=4, window_limit=2,
                                     window_seconds=100.0, updated_at=0.0),
                         request_id="req-policy-default", now=0.0)
    token = svc.issue_credential("brand-new-tenant", {"read"}, 1000.0,
                                 request_id="req-issue", now=0.0)
    st = svc.get_quota_status("brand-new-tenant", ENDPOINT, now=1.0)
    assert st["policy_source"] == "default"
    assert st["total_limit"] == 4 and st["window_limit"] == 2

    d1 = svc.authorize(token, ENDPOINT, "req-d1", now=1.0)
    d2 = svc.authorize(token, ENDPOINT, "req-d2", now=2.0)
    d3 = svc.authorize(token, ENDPOINT, "req-d3", now=3.0)  # 窗口层先到顶
    log_decision("default-window-deny", "req-d3", d3)
    assert d1.allowed and d2.allowed
    assert not d3.allowed and d3.reason is R.QUOTA_WINDOW_EXCEEDED
    # 不同租户各自分桶，互不影响
    other = svc.issue_credential("other-tenant", {"read"}, 1000.0,
                                 request_id="req-issue-2", now=0.0)
    assert svc.authorize(other, ENDPOINT, "req-other", now=3.0).allowed
    storage.close()


# ---- 2. 策略落盘后重启不丢，且老策略被替换后不再残留 ----
def test_policy_persists_across_restart_and_replacement_is_deterministic(tmp_path):
    db = str(tmp_path / "gov.db")
    storage1 = Storage(db)
    svc1 = _make_stack(storage1)
    svc1.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=3, window_limit=2,
                                      window_seconds=10.0, updated_at=1.0),
                          request_id="req-policy-v1", now=1.0)
    token = svc1.issue_credential("t1", {"read"}, 1000.0, request_id="req-issue", now=0.0)
    svc1.authorize(token, ENDPOINT, "req-before-1", now=1.0)
    svc1.authorize(token, ENDPOINT, "req-before-2", now=2.0)
    storage1.close()

    # 重启：不再手工下发，策略必须还在并按同一套规则判定
    storage2 = Storage(db)
    svc2 = _make_stack(storage2)
    policy, source = svc2._quota.effective_policy("t1", ENDPOINT)
    assert source == "exact"
    assert (policy.total_limit, policy.window_limit, policy.window_seconds) == (3, 2, 10.0)
    st = svc2.get_quota_status("t1", ENDPOINT, now=3.0)
    assert st["total_used"] == 2 and st["window_used"] == 2
    d = svc2.authorize(token, ENDPOINT, "req-after-restart", now=3.0)
    log_decision("restart-window-deny", "req-after-restart", d)
    assert not d.allowed and d.reason is R.QUOTA_WINDOW_EXCEEDED

    # 同一条策略反复下发：窗口层被去掉后老窗口限制不得残留
    svc2.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=100, window_limit=None,
                                      window_seconds=None, updated_at=4.0),
                          request_id="req-policy-v2", now=4.0)
    p, _ = svc2._quota.effective_policy("t1", ENDPOINT)
    assert p.total_limit == 100 and not p.has_window()
    d = svc2.authorize(token, ENDPOINT, "req-after-replace", now=4.0)
    log_decision("after-replace", "req-after-replace", d)
    assert d.allowed and d.extra["window_limit"] is None
    storage2.close()

    # 再重启：生效的仍是 v2，v1 永不复活
    storage3 = Storage(db)
    svc3 = _make_stack(storage3)
    p, source = svc3._quota.effective_policy("t1", ENDPOINT)
    assert source == "exact" and p.total_limit == 100 and p.window_limit is None
    storage3.close()


# ---- 3. 多窗口并发竞争：任何一层都不被突破，拒绝不吃计数 ----
def test_concurrent_window_race_never_exceeds_window(tmp_path):
    storage = Storage(str(tmp_path / "race.db"))
    svc = _make_stack(storage)
    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=100, window_limit=20,
                                     window_seconds=60.0, updated_at=0.0),
                         request_id="req-policy", now=0.0)
    token = svc.issue_credential("t1", {"read"}, 1000.0, request_id="req-issue", now=0.0)
    results, lock = [], threading.Lock()

    def worker(i):
        d = svc.authorize(token, ENDPOINT, f"req-race-{i}", now=1.0)
        with lock:
            results.append(d)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(128)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allowed = [d for d in results if d.allowed]
    denied = [d for d in results if not d.allowed]
    for d in denied[:3]:
        log_decision("window-race", d.request_id, d)
    assert len(allowed) == 20
    assert len(denied) == 108
    assert all(d.reason is R.QUOTA_WINDOW_EXCEEDED for d in denied)
    st = svc.get_quota_status("t1", ENDPOINT, now=1.0)
    assert st["window_used"] == 20 and st["total_used"] == 20  # 拒绝不吃计数
    storage.close()


def test_concurrent_total_layer_never_exceeds_total(tmp_path):
    """总量层并发：窗口放得很宽时，总量必须恰好卡住。"""
    storage = Storage(str(tmp_path / "race-total.db"))
    svc = _make_stack(storage)
    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=5, window_limit=10_000,
                                     window_seconds=60.0, updated_at=0.0),
                         request_id="req-policy", now=0.0)
    token = svc.issue_credential("t1", {"read"}, 1000.0, request_id="req-issue", now=0.0)
    results, lock = [], threading.Lock()

    def worker(i):
        d = svc.authorize(token, ENDPOINT, f"req-total-{i}", now=1.0)
        with lock:
            results.append(d)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(64)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(d.allowed for d in results) == 5
    denied = [d for d in results if not d.allowed]
    assert all(d.reason is R.QUOTA_EXCEEDED for d in denied)
    storage.close()


# ---- 窗口自然滚动与边界判定 ----
def test_window_rolls_and_boundary_is_stable():
    storage = Storage(":memory:")
    svc = _make_stack(storage)
    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=None, window_limit=2,
                                     window_seconds=10.0, updated_at=0.0),
                         request_id="req-policy", now=0.0)
    token = svc.issue_credential("t1", {"read"}, 1000.0, request_id="req-issue", now=0.0)

    assert svc.authorize(token, ENDPOINT, "req-w1", now=1.0).allowed
    assert svc.authorize(token, ENDPOINT, "req-w2", now=2.0).allowed
    d = svc.authorize(token, ENDPOINT, "req-w3", now=3.0)
    assert not d.allowed and d.reason is R.QUOTA_WINDOW_EXCEEDED

    # t=11：cutoff=1，ts<=1 的事件恰好滑出（半开区间 ts > now-N）
    d = svc.authorize(token, ENDPOINT, "req-w4", now=11.0)
    log_decision("window-roll", "req-w4", d)
    assert d.allowed and d.extra["window_used"] == 2
    # t=12：cutoff=2，ts=2 的事件滑出，窗口内只剩 t=11
    assert svc.authorize(token, ENDPOINT, "req-w5", now=12.0).allowed
    assert not svc.authorize(token, ENDPOINT, "req-w6", now=12.0).allowed
    storage.close()


def test_window_state_survives_restart(tmp_path):
    db = str(tmp_path / "window.db")
    storage1 = Storage(db)
    svc1 = _make_stack(storage1)
    svc1.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=None, window_limit=2,
                                      window_seconds=10.0, updated_at=0.0),
                          request_id="req-policy", now=0.0)
    token = svc1.issue_credential("t1", {"read"}, 1000.0, request_id="req-issue", now=0.0)
    svc1.authorize(token, ENDPOINT, "req-a", now=5.0)
    storage1.close()

    # 重启后窗口内事件仍在：同一窗口内再来 1 次后第 3 次必须被拦
    storage2 = Storage(db)
    svc2 = _make_stack(storage2)
    assert svc2.authorize(token, ENDPOINT, "req-b", now=6.0).allowed
    d = svc2.authorize(token, ENDPOINT, "req-c", now=7.0)
    assert not d.allowed and d.reason is R.QUOTA_WINDOW_EXCEEDED
    # 跨过窗口后自然恢复
    assert svc2.authorize(token, ENDPOINT, "req-d", now=16.0).allowed
    storage2.close()


# ---- 4. 放行请求同样可追溯：命中策略、当时用量与上限 ----
def test_allowed_and_denied_requests_are_traceable_by_request_id():
    storage = Storage(":memory:")
    svc = _make_stack(storage)
    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=1, window_limit=1,
                                     window_seconds=100.0, updated_at=0.0),
                         request_id="req-policy", now=0.0)
    token = svc.issue_credential("t1", {"read"}, 1000.0, request_id="req-issue", now=0.0)

    ok = svc.authorize(token, ENDPOINT, "req-trace-ok", now=1.0)
    assert ok.allowed
    no = svc.authorize(token, ENDPOINT, "req-trace-no", now=2.0)
    assert not no.allowed

    allowed_records = svc._audit.query(event="access_allowed")
    by_id = {r.request_id: r for r in allowed_records}
    assert "req-trace-ok" in by_id
    ex = by_id["req-trace-ok"].extra
    log_decision("trace-allow", "req-trace-ok", ok)
    print(f"[trace-allow-extra] {ex}")
    assert ex["policy_source"] == "exact"
    assert ex["total_limit"] == 1 and ex["total_used"] == 1
    assert ex["window_limit"] == 1 and ex["window_used"] == 1
    assert ex["window_seconds"] == 100.0

    denied = [r for r in svc._audit.query(event="access_denied")
              if r.request_id == "req-trace-no"]
    assert len(denied) == 1
    # 总量层与窗口层同时到顶时按总量层优先拒绝，结论确定可解释
    assert denied[0].reason == R.QUOTA_EXCEEDED.value
    storage.close()


# ---- 5. 策略/记账链路异常：必须拒绝，绝不静默放行 ----
def test_quota_chain_failure_denies_request():
    storage = Storage(":memory:")
    svc = _make_stack(storage)
    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=5, window_limit=None,
                                     window_seconds=None, updated_at=0.0),
                         request_id="req-policy", now=0.0)
    token = svc.issue_credential("t1", {"read"}, 1000.0, request_id="req-issue", now=0.0)

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    # 记账事务在计数阶段炸掉：限制器包装为 QuotaError，服务层拒绝放行
    svc._quota._storage.acquire_quota = boom
    d = svc.authorize(token, ENDPOINT, "req-chain-fail", now=1.0)
    log_decision("chain-fail", "req-chain-fail", d)
    assert not d.allowed and d.reason is R.QUOTA_UNAVAILABLE
    assert "quota chain failed" in d.detail
    # 失败期间没有任何计数落账
    assert svc._quota.usage("t1", ENDPOINT) == 0


def test_policy_load_failure_denies_request():
    storage = Storage(":memory:")
    svc = _make_stack(storage)
    token = svc.issue_credential("t1", {"read"}, 1000.0, request_id="req-issue", now=0.0)

    def boom(*args, **kwargs):
        raise QuotaError("policy table unavailable")

    svc._quota.effective_policy = boom
    d = svc.authorize(token, ENDPOINT, "req-policy-fail", now=1.0)
    log_decision("policy-fail", "req-policy-fail", d)
    assert not d.allowed and d.reason is R.QUOTA_UNAVAILABLE
    storage.close()


def test_invalid_policy_is_rejected():
    storage = Storage(":memory:")
    svc = _make_stack(storage)
    with pytest.raises(ValueError):
        svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=-1, window_limit=None,
                                         window_seconds=None, updated_at=0.0),
                             request_id="req-bad", now=0.0)
    with pytest.raises(ValueError):
        # 窗口两层参数必须成对出现
        svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=None, window_limit=5,
                                         window_seconds=None, updated_at=0.0),
                             request_id="req-bad2", now=0.0)
    storage.close()


def test_denied_request_rolls_back_window_pruning():
    """被拒绝的请求不产生任何写入：总量层拦截时，窗口过期事件的清理一并回滚。"""
    storage = Storage(":memory:")
    svc = _make_stack(storage)
    # 总量 1，窗口很宽；先造一笔已放行（窗口内留下事件），再把总量打满
    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=1, window_limit=100,
                                     window_seconds=10.0, updated_at=0.0),
                         request_id="p", now=0.0)
    token = svc.issue_credential("t1", {"read"}, 1000.0, request_id="issue", now=0.0)
    assert svc.authorize(token, ENDPOINT, "ok", now=1.0).allowed
    # t=100 时窗口早已滑过，但本次被总量层拒绝；物理事件不得因清理而消失
    d = svc.authorize(token, ENDPOINT, "denied-late", now=100.0)
    assert not d.allowed and d.reason is R.QUOTA_EXCEEDED
    assert storage.quota_window_usage("t1", ENDPOINT, 10.0, now=1.0) == 1
    # 调高总量后，同窗口口径下事件仍在（没有被拒绝请求偷删）
    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=10, window_limit=100,
                                     window_seconds=1000.0, updated_at=101.0),
                         request_id="p2", now=101.0)
    st = svc.get_quota_status("t1", ENDPOINT, now=101.0)
    assert st["window_used"] == 1 and st["total_used"] == 1
    storage.close()


# ---- 策略上调/下调结果确定 ----
def test_limit_adjust_up_and_down_is_deterministic():
    storage = Storage(":memory:")
    svc = _make_stack(storage)
    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=2, window_limit=None,
                                     window_seconds=None, updated_at=0.0),
                         request_id="p1", now=0.0)
    token = svc.issue_credential("t1", {"read"}, 1000.0, request_id="issue", now=0.0)
    svc.authorize(token, ENDPOINT, "a", now=1.0)
    svc.authorize(token, ENDPOINT, "b", now=1.0)
    assert not svc.authorize(token, ENDPOINT, "c", now=1.0).allowed

    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=3, window_limit=None,
                                     window_seconds=None, updated_at=2.0),
                         request_id="p2", now=2.0)
    assert svc.authorize(token, ENDPOINT, "d", now=2.0).allowed  # 上调立即生效

    svc.set_quota_policy(QuotaPolicy("t1", ENDPOINT, total_limit=1, window_limit=None,
                                     window_seconds=None, updated_at=3.0),
                         request_id="p3", now=3.0)
    # 下调到已用量之下：立即拒绝，老的 3 上限不再生效
    d = svc.authorize(token, ENDPOINT, "e", now=3.0)
    log_decision("limit-down", "e", d)
    assert not d.allowed and d.reason is R.QUOTA_EXCEEDED
    storage.close()
