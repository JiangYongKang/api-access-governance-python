"""测试公共夹具：隔离的数据目录与可控时钟。"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from governance.audit import AuditLog
from governance.persistence import GovernanceStore
from governance.service import GovernanceService
from tests.helpers import MutableClock


@pytest.fixture()
def clock() -> MutableClock:
    return MutableClock()


@pytest.fixture()
def service(tmp_path: Path, clock: MutableClock) -> Iterator[GovernanceService]:
    store = GovernanceStore(tmp_path / "state.json")
    store.load()
    audit = AuditLog(tmp_path / "audit.jsonl", clock=clock)
    svc = GovernanceService(store, audit, clock=clock)
    counter = {"n": 0}

    def id_factory() -> str:
        counter["n"] += 1
        return f"req-{counter['n']}"

    svc._id_factory = id_factory
    yield svc
