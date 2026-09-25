"""并发配额竞争与幽灵配额测试。

结论可复现性:
- N 个并发请求、配额上限 L 时，放行数严格等于 min(N, L)，
  审计 allow 条数、配额 used 三者必须严格一致（无幽灵配额、无超卖）。
- 所有被拒绝请求的 reason 必须是 quota_exceeded 且携带请求标识。
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from governance.errors import DenyReason, GovernanceError
from tests.helpers import MutableClock, log_decision

logger = logging.getLogger("test.quota")

ENDPOINT = "GET /tenant/data"
SCOPE = "read:data"


def test_concurrent_requests_never_exceed_limit(service) -> None:
    svc = service
    limit = 50
    n_requests = 200
    svc.quotas.set_limit("t1", ENDPOINT, limit=limit, window_seconds=3600)
    tokens = [
        svc.issue_credential("t1", {SCOPE})[1] for _ in range(8)
    ]
    results: list[tuple[str, bool, str]] = []
    lock = logging.Lock if False else threading.Lock()  # 仅保护结果列表

    def call(i: int) -> tuple[str, bool, str]:
        rid = f"conc-{i:03d}"
        tok = tokens[i % len(tokens)]
        try:
            svc.authorize(tok, ENDPOINT, SCOPE, request_id=rid)
            with lock:
                results.append((rid, True, "allow"))
            log_decision(rid, "authorize", decision="allow", rule="quota.limit")
            return rid, True, "allow"
        except GovernanceError as exc:
            assert exc.reason is DenyReason.QUOTA_EXCEEDED, (rid, exc.reason)
            with lock:
                results.append((rid, False, exc.reason.value))
            log_decision(rid, "authorize", decision="deny",
                         rule=exc.rule, reason=exc.reason.value)
            return rid, False, exc.reason.value

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = [pool.submit(call, i) for i in range(n_requests)]
        list(as_completed(futures))
        for f in futures:
            f.result()  # 任何线程内断言失败在此暴露

    allowed = [r for r in results if r[1]]
    denied = [r for r in results if not r[1]]

    # 1) 不超卖
    assert len(allowed) == limit, len(allowed)
    # 2) 拒绝全部可区分且可复现
    assert len(denied) == n_requests - limit
    assert all(r[2] == "quota_exceeded" for r in denied)
    # 3) 无幽灵配额：落盘用量 == 放行数
    assert svc._store.get_quota("t1", ENDPOINT).used == limit
    # 4) 审计 allow 条数 == 放行数；deny 条数 == 拒绝数，且一一带 request_id
    audit_allows = svc.audit.query(decision="allow", limit=10_000)
    audit_denies = svc.audit.query(decision="deny", limit=10_000)
    assert len(audit_allows) == limit
    assert len(audit_denies) == n_requests - limit
    allow_ids = {e.request_id for e in audit_allows}
    assert allow_ids == {r[0] for r in allowed}
    for e in audit_denies:
        assert e.reason == "quota_exceeded"
        assert e.rule == "quota.limit"
    logger.info(
        "并发竞争结论: 总请求=%d 放行=%d 拒绝=%d used=%d",
        n_requests, len(allowed), len(denied),
        svc._store.get_quota("t1", ENDPOINT).used,
    )


def test_denied_requests_have_no_ghost_quota(service) -> None:
    """认证失败的请求一律不得消耗配额。"""
    svc = service
    svc.quotas.set_limit("t1", ENDPOINT, limit=3, window_seconds=3600)
    _, good = svc.issue_credential("t1", {SCOPE})
    _, no_scope = svc.issue_credential("t1", {"other"})

    bad_inputs = [
        (None, DenyReason.MISSING_CREDENTIAL, "ghost-missing"),
        ("bad-token", DenyReason.UNTRUSTED_FORMAT, "ghost-format"),
        (no_scope, DenyReason.INSUFFICIENT_SCOPE, "ghost-scope"),
    ]
    for tok, expected, rid in bad_inputs:
        with pytest.raises(GovernanceError) as ei:
            svc.authorize(tok, ENDPOINT, SCOPE, request_id=rid)
        assert ei.value.reason is expected
    assert svc._store.get_quota("t1", ENDPOINT).used == 0

    # 之后的正常请求仍可拿到全部 3 个配额
    for i in range(3):
        assert svc.authorize(good, ENDPOINT, SCOPE, request_id=f"real-{i}").allowed
    assert svc._store.get_quota("t1", ENDPOINT).used == 3


def test_quota_persists_across_restart(tmp_path, service) -> None:
    """配额状态持久化：重启后同一窗口内结论保持一致。"""
    svc = service
    svc.quotas.set_limit("t1", ENDPOINT, limit=2, window_seconds=3600)
    _, tok = svc.issue_credential("t1", {SCOPE})
    svc.authorize(tok, ENDPOINT, SCOPE, request_id="before-restart-1")
    svc.authorize(tok, ENDPOINT, SCOPE, request_id="before-restart-2")

    from governance.persistence import GovernanceStore
    store = GovernanceStore(tmp_path / "state.json")
    store.load()
    restarted = svc.__class__(store, svc.audit, clock=svc._clock)
    with pytest.raises(GovernanceError) as ei:
        restarted.authorize(tok, ENDPOINT, SCOPE, request_id="after-restart")
    assert ei.value.reason is DenyReason.QUOTA_EXCEEDED


def test_fixed_window_rolls_over(service, clock: MutableClock) -> None:
    """固定窗口结束后计数清零，结论随时间确定复现。"""
    svc = service
    svc.quotas.set_limit("t1", ENDPOINT, limit=2, window_seconds=100)
    _, tok = svc.issue_credential("t1", {SCOPE})
    svc.authorize(tok, ENDPOINT, SCOPE, request_id="w1-1")
    svc.authorize(tok, ENDPOINT, SCOPE, request_id="w1-2")
    with pytest.raises(GovernanceError):
        svc.authorize(tok, ENDPOINT, SCOPE, request_id="w1-3")
    clock.advance(101)
    decision = svc.authorize(tok, ENDPOINT, SCOPE, request_id="w2-1")
    assert decision.allowed
    assert svc._store.get_quota("t1", ENDPOINT).used == 1
