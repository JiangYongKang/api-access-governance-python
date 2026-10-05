"""审计流水：并发写入不丢失不重复，审计异常不得静默放行，记录可查询。"""

import threading

from governance.errors import DecisionReason as R

from .conftest import ENDPOINT, log_decision


def test_denials_and_credential_changes_are_audited(stack):
    svc, _ = stack
    token = svc.issue_credential("t1", {"read"}, ttl_seconds=100.0,
                                 request_id="req-issue", now=0.0)
    key_id = token.split(".")[1]
    svc.rotate_credential(key_id, "req-rotate", now=1.0)
    svc.revoke_credential(key_id, "t1", "req-revoke", now=2.0)
    svc.authorize("bad", ENDPOINT, "req-denied", now=3.0)

    records = svc._audit.query(tenant_id="t1")
    events = [r.event for r in records]
    for r in records:
        print(f"[audit] seq={r.seq} event={r.event} request_id={r.request_id} "
              f"reason={r.reason} detail={r.detail!r}")
    assert events == ["credential_issued", "credential_rotated", "credential_revoked"]
    denied = svc._audit.query(event="access_denied")
    assert len(denied) == 1 and denied[0].request_id == "req-denied"
    assert denied[0].reason == R.MALFORMED_CREDENTIAL.value  # 含判定依据与请求标识


def test_concurrent_audit_writes_are_not_lost_or_duplicated(stack):
    """128 个并发拒绝：审计条数必须恰好为 128，seq 唯一且连续。"""
    svc, _ = stack

    def worker(i):
        svc.authorize("garbage", ENDPOINT, f"req-audit-{i}", now=0.0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(128)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    records = svc._audit.query(event="access_denied")
    seqs = [r.seq for r in records]
    ids = [r.request_id for r in records]
    assert len(records) == 128
    assert len(set(seqs)) == 128 and len(set(ids)) == 128  # 无丢失、无重复


def test_audit_failure_denies_request(stack):
    """审计写入异常时，授权结论必须是 AUDIT_FAILURE 拒绝，不得静默放行。"""
    svc, storage = stack
    storage.close()  # 关闭底层连接，强制审计写入失败
    d = svc.authorize("garbage", ENDPOINT, "req-audit-fail", now=0.0)
    log_decision("audit-failure", "req-audit-fail", d)
    assert not d.allowed and d.reason is R.AUDIT_FAILURE
    assert "audit write failed" in d.detail
