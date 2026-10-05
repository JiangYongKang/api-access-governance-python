import os
import tempfile

import pytest

# 在导入 main 之前把模块级装配的数据库指向临时文件，避免在仓库根目录落 governance.db
os.environ.setdefault(
    "GOVERNANCE_DB", os.path.join(tempfile.gettempdir(), "governance-pytest.db"))

from governance.audit import AuditLog
from governance.credentials import CredentialManager
from governance.quota import QuotaLimiter
from governance.service import GovernanceService
from governance.storage import Storage

ENDPOINT = "/data"
GRACE = 10.0


def make_service(storage):
    """完整治理栈：/data 需要 read scope。策略由各用例自行下发。"""
    return GovernanceService(
        credentials=CredentialManager(storage, grace_seconds=GRACE),
        quota=QuotaLimiter(storage),
        audit=AuditLog(storage),
        endpoint_scopes={ENDPOINT: "read"},
    )


@pytest.fixture()
def stack():
    """内存存储的治理栈：t1 在 /data 上总量上限为 5（保持旧用例语义）。"""
    storage = Storage(":memory:")
    svc = make_service(storage)
    svc._quota.set_limit("t1", ENDPOINT, 5)
    yield svc, storage
    storage.close()


def log_decision(tag, request_id, decision):
    """测试日志：打印请求标识、命中的规则、判定依据与当时的两层用量/上限。"""
    print(f"[{tag}] request_id={request_id} allowed={decision.allowed} "
          f"rule={decision.reason.value} layer={decision.limiting_layer} "
          f"source={decision.policy_source} "
          f"total={decision.total_used}/{decision.total_limit} "
          f"window={decision.window_used}/{decision.window_limit}"
          f"@{decision.window_seconds}s detail={decision.detail!r}")
