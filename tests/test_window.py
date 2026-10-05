"""滚动时间窗口：自然滚动/重置、与总量叠加、边界稳定、并发不越界、无幽灵计数。"""

import threading

from governance.errors import DecisionReason as R

from .conftest import ENDPOINT, log_decision


def _setup(svc, tenant="t1", total=None, window_seconds=10.0, window_limit=2):
    svc._quota.set_policy(tenant, ENDPOINT, total_limit=total,
                          window_seconds=window_seconds, window_limit=window_limit)
    return svc.issue_credential(tenant, {"read"}, 10000.0, "req-issue", now=0.0)


def test_window_rolls_and_resets(stack):
    """窗口随时间自然滚动：窗口外的旧事件不再计数，窗口到点后恢复放行。"""
    svc, _ = stack
    token = _setup(svc, window_seconds=10.0, window_limit=2)

    assert svc.authorize(token, ENDPOINT, "w1", now=0.0).allowed
    assert svc.authorize(token, ENDPOINT, "w2", now=5.0).allowed
    d = svc.authorize(token, ENDPOINT, "w3", now=9.9)
    log_decision("window-full", "w3", d)
    assert not d.allowed and d.reason is R.RATE_LIMITED
    assert d.limiting_layer == "window"

    # t=10.0：窗口区间 (0,10]，t=0 的事件已滑出（ts <= now-window 被清理）
    d_reset = svc.authorize(token, ENDPOINT, "w4", now=10.0)
    log_decision("window-edge", "w4", d_reset)
    assert d_reset.allowed  # 边界判定稳定可解释

    # t=15.0：窗口区间 (5,15]，t=5 的事件恰好滑出，只剩 t=10 一条 -> 放行
    d2 = svc.authorize(token, ENDPOINT, "w5", now=15.0)
    assert d2.allowed
    # 紧接下一次：(5,15] 内已有 t=10、t=15 两条 -> 拒绝
    d2b = svc.authorize(token, ENDPOINT, "w5b", now=15.0)
    log_decision("window-edge2", "w5b", d2b)
    assert not d2b.allowed and d2b.reason is R.RATE_LIMITED
    # t=20.001：t=10 滑出，只剩 t=15 一条 -> 放行
    d3 = svc.authorize(token, ENDPOINT, "w6", now=20.001)
    assert d3.allowed


def test_total_and_window_both_apply_and_layer_is_reported(stack):
    """总量层与窗口层叠加：任意一层到顶即拒绝，且能区分被哪一层拦下。"""
    svc, _ = stack
    # 总量 5；每 100s 窗口 2
    token = _setup(svc, total=5, window_seconds=100.0, window_limit=2)

    svc.authorize(token, ENDPOINT, "a1", now=1.0)
    svc.authorize(token, ENDPOINT, "a2", now=1.0)
    d_window = svc.authorize(token, ENDPOINT, "a3", now=1.0)
    log_decision("layer-window", "a3", d_window)
    assert not d_window.allowed and d_window.reason is R.RATE_LIMITED
    assert d_window.limiting_layer == "window"
    assert svc._quota.usage("t1", ENDPOINT) == 2  # 拒绝不吃计数

    # 窗口滑过后继续放行，直到总量层到顶
    for rid, ts in [("a4", 101.0), ("a5", 201.0), ("a6", 301.0)]:
        d = svc.authorize(token, ENDPOINT, rid, now=ts)
        assert d.allowed, rid
    d_total = svc.authorize(token, ENDPOINT, "a7", now=401.0)
    log_decision("layer-total", "a7", d_total)
    assert not d_total.allowed and d_total.reason is R.QUOTA_EXCEEDED
    assert d_total.limiting_layer == "total"
    assert svc._quota.usage("t1", ENDPOINT) == 5


def test_concurrent_window_race_never_exceeds(stack):
    """128 线程竞争窗口上限 10：放行数恰好 10，窗口计数不越界。"""
    svc, _ = stack
    token = _setup(svc, total=None, window_seconds=10.0, window_limit=10)
    results, lock = [], threading.Lock()

    def worker(i):
        d = svc.authorize(token, ENDPOINT, f"race-{i}", now=1.0)
        with lock:
            results.append(d)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(128)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allowed = [d for d in results if d.allowed]
    denied = [d for d in results if not d.allowed]
    assert len(allowed) == 10
    assert len(denied) == 118
    assert all(d.reason is R.RATE_LIMITED and d.limiting_layer == "window"
               for d in denied)
    assert svc._quota.window_usage("t1", ENDPOINT, 10.0, now=1.0) == 10


def test_concurrent_two_layers_never_exceed_either(stack):
    """总量 6 + 窗口 4 同时竞争：放行数受更紧的窗口约束为 4，两层都不越界。"""
    svc, _ = stack
    token = _setup(svc, total=6, window_seconds=10.0, window_limit=4)
    results, lock = [], threading.Lock()

    def worker(i):
        d = svc.authorize(token, ENDPOINT, f"both-{i}", now=1.0)
        with lock:
            results.append(d)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(64)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len([d for d in results if d.allowed]) == 4
    assert svc._quota.usage("t1", ENDPOINT) == 4
    assert svc._quota.window_usage("t1", ENDPOINT, 10.0, now=1.0) == 4


def test_denied_requests_leave_no_window_ghost(stack):
    """被窗口拒绝的请求不得在窗口表中留下事件（无幽灵窗口计数）。"""
    svc, _ = stack
    token = _setup(svc, window_seconds=10.0, window_limit=1)
    assert svc.authorize(token, ENDPOINT, "g1", now=1.0).allowed
    for i in range(5):
        d = svc.authorize(token, ENDPOINT, f"g-deny-{i}", now=1.0)
        assert not d.allowed
    # 仍只有 1 个窗口事件；窗口滑过后立刻可再放行 1 次
    assert svc._quota.window_usage("t1", ENDPOINT, 10.0, now=1.0) == 1
    d = svc.authorize(token, ENDPOINT, "g2", now=11.0)
    assert d.allowed


def test_window_state_survives_restart(tmp_path):
    """窗口事件持久化：重启后窗口内已用量保持，到顶仍拒绝；滑过后恢复。"""
    from governance.storage import Storage

    from .conftest import make_service

    db = str(tmp_path / "win.db")
    s1 = Storage(db)
    svc1 = make_service(s1)
    token = _setup(svc1, window_seconds=10.0, window_limit=2)
    assert svc1.authorize(token, ENDPOINT, "p1", now=1.0).allowed
    assert svc1.authorize(token, ENDPOINT, "p2", now=2.0).allowed
    s1.close()

    s2 = Storage(db)
    svc2 = make_service(s2)
    d = svc2.authorize(token, ENDPOINT, "p3", now=3.0)  # 重启后窗口仍满
    log_decision("restart-window", "p3", d)
    assert not d.allowed and d.reason is R.RATE_LIMITED
    d2 = svc2.authorize(token, ENDPOINT, "p4", now=12.1)  # 窗口滑过
    assert d2.allowed
    s2.close()
