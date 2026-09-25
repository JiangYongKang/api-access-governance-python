"""轮换/撤销生效期间的在途请求语义测试（并发可复现）。

由于授权判定与状态变更在同一把 store 锁内串行化，每个在途请求的结论
只取决于它进入临界区时读到的状态：
- 轮换设置非零兼容窗口：窗口内进入临界区的旧凭证请求必然放行；
  窗口结束后进入的旧凭证请求必然 grace_window_closed。
- 立即撤销：在 revoke 落盘之后进入临界区的旧凭证请求必然撤销拒绝。
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from governance.errors import DenyReason, GovernanceError

logger = logging.getLogger("test.inflight")

ENDPOINT = "GET /tenant/data"
SCOPE = "read:data"


def test_inflight_requests_during_rotation_grace(service) -> None:
    svc = service
    _, old_tok = svc.issue_credential("t1", {SCOPE})
    # 先制造一批持有旧凭证的在途请求；轮换带 3600s 兼容窗口
    def old_request(i: int) -> str:
        rid = f"inflight-{i}"
        try:
            svc.authorize(old_tok, ENDPOINT, SCOPE, request_id=rid)
            logger.info("request_id=%s rule=%s 旧凭证在途=放行", rid, "credential.ok")
            return "allow"
        except GovernanceError as exc:
            logger.info(
                "request_id=%s rule=%s reason=%s 旧凭证在途=拒绝",
                rid, exc.rule, exc.reason.value,
            )
            return exc.reason.value

    barrier = threading.Barrier(20 + 1)

    def worker(i: int) -> str:
        barrier.wait()
        return old_request(i)

    with ThreadPoolExecutor(max_workers=21) as pool:
        futures = [pool.submit(worker, i) for i in range(20)]
        # 主线程作为轮换者与 20 个请求同时冲过栅栏
        def rotate() -> str:
            barrier.wait()
            _new_id, new_tok = svc.rotate_credential(
                # 旧 id 通过凭证列表取到
                svc._store.list_credentials("t1")[0].credential_id,
                grace_period=3600,
                request_id="rotation-op",
            )
            return new_tok

        rot_future = pool.submit(rotate)
        outcomes = [f.result() for f in futures]
        new_tok = rot_future.result()

    # 兼容窗口内：无论请求在轮换提交前还是后进入临界区，旧凭证全部放行，
    # 结论集合确定（不存在偶发拒绝）。
    assert set(outcomes) == {"allow"}, outcomes
    # 新凭证可用
    assert svc.authorize(new_tok, ENDPOINT, SCOPE, request_id="new-token").allowed


def test_immediate_revoke_blocks_subsequent_inflight(service) -> None:
    svc = service
    old_id, old_tok = svc.issue_credential("t1", {SCOPE})
    results: dict[str, str] = {}
    lock = threading.Lock()

    start = threading.Event()

    def attempt(rid: str) -> None:
        start.wait()
        try:
            svc.authorize(old_tok, ENDPOINT, SCOPE, request_id=rid)
            outcome = "allow"
        except GovernanceError as exc:
            outcome = exc.reason.value
            assert exc.reason is DenyReason.REVOKED_CREDENTIAL
        with lock:
            results[rid] = outcome

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(attempt, f"post-revoke-{i}") for i in range(10)]
        # 撤销先行并确保落盘，再放行工作线程
        svc.revoke_credential(old_id, grace_period=0.0, request_id="revoke-op")
        start.set()
        for f in futures:
            f.result()

    # revoke 落盘后进入临界区的全部请求必然 revoked，结论可复现
    assert set(results.values()) == {"revoked_credential"}, results
    rows = svc.audit.query(request_id="revoke-op")
    assert len(rows) == 1 and rows[0].decision == "credential_revoked"


def test_inflight_audit_trail_complete(service) -> None:
    """在途请求无论放行拒绝，审计都带请求标识、规则与依据，无重复无丢失。"""
    svc = service
    _old_id, old_tok = svc.issue_credential("t1", {SCOPE})
    svc.quotas.set_limit("t1", ENDPOINT, limit=1, window_seconds=3600)

    rids = [f"audit-trail-{i}" for i in range(5)]
    outcomes: dict[str, str] = {}
    for rid in rids:
        try:
            svc.authorize(old_tok, ENDPOINT, SCOPE, request_id=rid)
            outcomes[rid] = "allow"
        except GovernanceError as exc:
            outcomes[rid] = exc.reason.value

    allows = [r for r, v in outcomes.items() if v == "allow"]
    denies = [r for r, v in outcomes.items() if v == "quota_exceeded"]
    assert len(allows) == 1 and len(denies) == 4

    # 每个请求标识恰好对应一条审计记录（无丢失、无重复）
    for rid in rids:
        rows = svc.audit.query(request_id=rid, limit=1000)
        assert len(rows) == 1, (rid, len(rows))
        assert rows[0].rule  # 命中规则非空
        assert rows[0].detail  # 判定依据非空
