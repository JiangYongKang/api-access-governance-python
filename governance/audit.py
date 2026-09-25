"""审计流水：拒绝请求与凭证变更的可查询记录。

存储采用本地 JSONL 追加文件，进程内用一把锁串行化所有追加；每次写入
后 flush + fsync，崩溃不丢已确认的记录。查询按租户/请求标识/判定结果
过滤。审计环节本身异常时，编排层必须把请求判为拒绝
（``AUDIT_FAILURE``），绝不静默放行。
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict
from pathlib import Path

from governance.errors import AuditError
from governance.model import AuditEntry

_DECISIONS = frozenset(
    {
        "allow",
        "deny",
        "credential_issued",
        "credential_rotated",
        "credential_revoked",
    }
)


class AuditLog:
    """线程安全的本地 JSONL 审计流水。"""

    def __init__(
        self,
        path: str | Path,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._clock = clock or time.time

    def _now(self) -> float:
        return self._clock()

    def append(self, entry: AuditEntry) -> None:
        """追加一条审计记录并持久化（flush+fsync）。

        失败时抛出 :class:`AuditError`，调用方负责拒绝请求。
        """
        if entry.decision not in _DECISIONS:
            raise AuditError(f"非法的审计 decision: {entry.decision!r}")
        line = json.dumps(asdict(entry), ensure_ascii=False)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock, self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise AuditError(f"审计流水写入失败 {self.path}: {exc}") from exc

    def query(
        self,
        tenant: str | None = None,
        request_id: str | None = None,
        decision: str | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """按条件倒序查询审计记录（最多返回 ``limit`` 条）。"""
        matches: list[AuditEntry] = []
        for entry in self.read_all():
            if tenant is not None and entry.tenant != tenant:
                continue
            if request_id is not None and entry.request_id != request_id:
                continue
            if decision is not None and entry.decision != decision:
                continue
            matches.append(entry)
        matches.reverse()
        return matches[:limit]

    def read_all(self) -> Iterable[AuditEntry]:
        """读取全部记录（正序）。坏行抛 :class:`AuditError`，不静默跳过。"""
        if not self.path.exists():
            return []
        entries: list[AuditEntry] = []
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                        entries.append(AuditEntry(**raw))
                    except (json.JSONDecodeError, TypeError) as exc:
                        raise AuditError(
                            f"审计流水第 {lineno} 行损坏: {exc}"
                        ) from exc
        except OSError as exc:
            raise AuditError(f"审计流水读取失败 {self.path}: {exc}") from exc
        return entries
