"""审计流水：拒绝请求与凭证变更的可查询记录。

写入失败会抛出 AuditWriteError；授权链路必须将其视为拒绝，不得静默放行。
"""

from __future__ import annotations

import uuid

from .errors import AuditWriteError
from .models import AuditRecord
from .storage import Storage


def new_request_id() -> str:
    return uuid.uuid4().hex


class AuditLog:
    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def record(self, event: str, request_id: str, tenant_id: str, reason: str,
               detail: str = "", extra: dict | None = None, now: float = 0.0) -> None:
        """写入一条审计记录；失败时抛出 AuditWriteError。"""
        try:
            self._storage.append_audit(AuditRecord(
                seq=0, ts=now, event=event, request_id=request_id, tenant_id=tenant_id,
                reason=reason, detail=detail, extra=extra or {},
            ))
        except AuditWriteError:
            raise
        except Exception as exc:  # 存储层异常统一包装，避免泄露实现细节
            raise AuditWriteError(f"audit append failed: {exc}") from exc

    def query(self, tenant_id: str | None = None, event: str | None = None) -> list[AuditRecord]:
        return self._storage.query_audit(tenant_id=tenant_id, event=event)
