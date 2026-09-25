"""审计环节异常时的安全失效（fail-closed）测试。

审计写入失败：
- 认证通过的请求也必须被拒绝（AUDIT_FAILURE），且配额不得预占；
- 认证本来就拒绝的请求维持拒绝，错误升级为 AUDIT_FAILURE；
- 审计流水本身在并发追加下不丢不重。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from governance.audit import AuditLog
from governance.errors import AuditError, DenyReason, GovernanceError
from governance.model import AuditEntry

ENDPOINT = "GET /tenant/data"
SCOPE = "read:data"


class BrokenAudit(AuditLog):
    """始终写入失败的审计实现。"""

    def append(self, entry: AuditEntry) -> None:
        raise AuditError("simulated disk failure")


def test_audit_failure_denies_allow_path_without_quota(service) -> None:
    svc = service
    svc.quotas.set_limit("t1", ENDPOINT, limit=5, window_seconds=3600)
    _, tok = svc.issue_credential("t1", {SCOPE})
    svc._audit = BrokenAudit(svc.audit.path)

    with pytest.raises(GovernanceError) as ei:
        svc.authorize(tok, ENDPOINT, SCOPE, request_id="audit-boom-allow")
    assert ei.value.reason is DenyReason.AUDIT_FAILURE
    assert ei.value.request_id == "audit-boom-allow"
    # 未消耗任何配额（无幽灵配额）
    assert svc._store.get_quota("t1", ENDPOINT).used == 0


def test_audit_failure_still_denies_unauthenticated(service) -> None:
    svc = service
    svc._audit = BrokenAudit(svc.audit.path)
    with pytest.raises(GovernanceError) as ei:
        svc.authorize(None, ENDPOINT, SCOPE, request_id="audit-boom-deny")
    # 绝不静默放行：错误升级为 AUDIT_FAILURE
    assert ei.value.reason is DenyReason.AUDIT_FAILURE


def test_concurrent_audit_appends_no_loss_no_duplicate(service) -> None:
    svc = service
    n = 100

    def write(i: int) -> None:
        svc.audit.append(
            AuditEntry(
                request_id=f"w-{i}",
                timestamp=float(i),
                tenant="t1",
                endpoint="e",
                decision="allow",
                rule="test",
                detail="x",
            )
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(write, range(n)))
    rows = list(svc.audit.read_all())
    ids = [r.request_id for r in rows]
    assert len(ids) == n
    assert len(set(ids)) == n  # 无重复
