"""配额并发竞争与持久化：并发不得突破上限，不得出现幽灵配额，重启后结论一致。"""

import threading

from governance.audit import AuditLog
from governance.credentials import CredentialManager
from governance.errors import DecisionReason as R
from governance.quota import QuotaLimiter
from governance.service import GovernanceService
from governance.storage import Storage

from .conftest import ENDPOINT, log_decision


def _make_stack(storage):
    svc = GovernanceService(
        credentials=CredentialManager(storage),
        quota=QuotaLimiter(storage),
        audit=AuditLog(storage),
        endpoint_scopes={ENDPOINT: "read"},
    )
    return svc


def test_concurrent_quota_race_never_exceeds_limit(stack):
    """64 线程并发竞争上限为 5 的配额：放行数必须恰好为 5，无超扣。"""
    svc, _ = stack
    token = svc.issue_credential("t1", {"read"}, ttl_seconds=1000.0,
                                 request_id="req-issue", now=0.0)
    results, lock = [], threading.Lock()

    def worker(i):
        rid = f"req-race-{i}"
        d = svc.authorize(token, ENDPOINT, rid, now=1.0)
        with lock:
            results.append(d)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(64)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allowed = [d for d in results if d.allowed]
    denied = [d for d in results if not d.allowed]
    for d in denied[:3]:
        log_decision("quota-race", d.request_id, d)
    assert len(allowed) == 5
    assert len(denied) == 59
    assert all(d.reason is R.QUOTA_EXCEEDED for d in denied)
    assert svc._quota.usage("t1", ENDPOINT) == 5  # 计数与实际放行一致


def test_denied_requests_do_not_consume_quota(stack):
    """幽灵配额检查：凭证类拒绝发生在配额扣减之前，不得占用配额。"""
    svc, _ = stack
    good = svc.issue_credential("t1", {"read"}, ttl_seconds=1000.0,
                                request_id="req-issue", now=0.0)
    for i in range(20):  # 大量格式错误的请求
        svc.authorize("garbage", ENDPOINT, f"req-bad-{i}", now=1.0)
    assert svc._quota.usage("t1", ENDPOINT) == 0
    for i in range(5):  # 合法请求仍可全额放行
        d = svc.authorize(good, ENDPOINT, f"req-good-{i}", now=1.0)
        assert d.allowed
    assert svc._quota.usage("t1", ENDPOINT) == 5


def test_quota_state_survives_restart(tmp_path):
    """配额持久化：用同一数据库文件重建治理栈后，已用量与判定结论保持一致。"""
    db = str(tmp_path / "gov.db")
    svc1 = _make_stack(Storage(db))
    svc1._quota.set_limit("t1", ENDPOINT, 3)
    token = svc1.issue_credential("t1", {"read"}, ttl_seconds=1000.0,
                                  request_id="req-issue", now=0.0)
    for i in range(3):
        assert svc1.authorize(token, ENDPOINT, f"req-before-{i}", now=1.0).allowed

    # 模拟重启：同一文件新建存储与服务
    svc2 = _make_stack(Storage(db))
    svc2._quota.set_limit("t1", ENDPOINT, 3)
    assert svc2._quota.usage("t1", ENDPOINT) == 3
    d = svc2.authorize(token, ENDPOINT, "req-after-restart", now=2.0)
    log_decision("after-restart", "req-after-restart", d)
    assert not d.allowed and d.reason is R.QUOTA_EXCEEDED  # 重启后结论一致
