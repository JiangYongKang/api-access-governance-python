import pytest

from governance.audit import AuditLog
from governance.credentials import CredentialManager
from governance.quota import QuotaLimiter
from governance.service import GovernanceService
from governance.storage import Storage

ENDPOINT = "/data"
GRACE = 10.0


@pytest.fixture()
def stack():
    """内存存储的完整治理栈：t1 在 /data 上配额为 5，/data 需要 read scope。"""
    storage = Storage(":memory:")
    svc = GovernanceService(
        credentials=CredentialManager(storage, grace_seconds=GRACE),
        quota=QuotaLimiter(storage),
        audit=AuditLog(storage),
        endpoint_scopes={ENDPOINT: "read"},
    )
    svc._quota.set_limit("t1", ENDPOINT, 5)
    yield svc, storage
    storage.close()


def log_decision(tag, request_id, decision):
    """测试日志：打印请求标识、命中的规则与判定依据。"""
    print(f"[{tag}] request_id={request_id} allowed={decision.allowed} "
          f"rule={decision.reason.value} detail={decision.detail!r}")
