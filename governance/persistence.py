"""本地持久化：单文件 JSON + 进程内锁 + 原子落盘。

所有治理状态（凭证、配额）保存在同一个 :class:`GovernanceStore` 中，
通过一把 ``threading.RLock`` 保证并发判定串行化；写操作以
"临时文件 + os.replace" 原子替换，崩溃或重启后读到的要么是旧版本
要么是新版本，不会出现半截文件。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

from governance.errors import StorageError
from governance.model import CredentialRecord, QuotaState


class GovernanceStore:
    """凭证与配额状态的本地持久化容器。"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._credentials: dict[str, CredentialRecord] = {}
        self._quotas: dict[tuple[str, str], QuotaState] = {}

    @property
    def lock(self) -> threading.RLock:
        """对外暴露的状态大锁，编排层在一个临界区内完成判定+配额+落盘。"""
        return self._lock

    def load(self) -> None:
        """从磁盘加载状态；文件不存在时视为空状态。"""
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StorageError(f"无法加载治理状态文件 {self.path}: {exc}") from exc
        creds: dict[str, CredentialRecord] = {}
        for item in raw.get("credentials", []):
            creds[item["credential_id"]] = CredentialRecord(
                credential_id=item["credential_id"],
                tenant=item["tenant"],
                scopes=frozenset(item.get("scopes", [])),
                token_hash=item.get("token_hash", ""),
                version=item.get("version", 1),
                issued_at=item.get("issued_at", 0.0),
                expires_at=item.get("expires_at"),
                revoked_at=item.get("revoked_at"),
                grace_until=item.get("grace_until"),
                superseded_by=item.get("superseded_by"),
            )
        quotas: dict[tuple[str, str], QuotaState] = {}
        for item in raw.get("quotas", []):
            state = QuotaState(
                tenant=item["tenant"],
                endpoint=item["endpoint"],
                limit=item["limit"],
                window_seconds=item.get("window_seconds", 60.0),
                used=item.get("used", 0),
                window_start=item.get("window_start", 0.0),
            )
            quotas[(state.tenant, state.endpoint)] = state
        self._credentials = creds
        self._quotas = quotas

    def persist(self) -> None:
        """原子落盘当前全部状态。调用方必须持有 ``lock``。"""
        payload = {
            "version": 1,
            "credentials": [
                {
                    "credential_id": r.credential_id,
                    "tenant": r.tenant,
                    "scopes": sorted(r.scopes),
                    "token_hash": r.token_hash,
                    "version": r.version,
                    "issued_at": r.issued_at,
                    "expires_at": r.expires_at,
                    "revoked_at": r.revoked_at,
                    "grace_until": r.grace_until,
                    "superseded_by": r.superseded_by,
                }
                for r in self._credentials.values()
            ],
            "quotas": [
                {
                    "tenant": q.tenant,
                    "endpoint": q.endpoint,
                    "limit": q.limit,
                    "window_seconds": q.window_seconds,
                    "used": q.used,
                    "window_start": q.window_start,
                }
                for q in self._quotas.values()
            ],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd, tmp_name = tempfile.mkstemp(
                prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, ensure_ascii=False, indent=2)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, self.path)
            finally:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
        except OSError as exc:
            raise StorageError(f"治理状态落盘失败 {self.path}: {exc}") from exc

    def get_credential(self, credential_id: str) -> CredentialRecord | None:
        return self._credentials.get(credential_id)

    def put_credential(self, record: CredentialRecord) -> None:
        self._credentials[record.credential_id] = record

    def list_credentials(self, tenant: str | None = None) -> list[CredentialRecord]:
        if tenant is None:
            return list(self._credentials.values())
        return [r for r in self._credentials.values() if r.tenant == tenant]

    def get_quota(self, tenant: str, endpoint: str) -> QuotaState | None:
        return self._quotas.get((tenant, endpoint))

    def put_quota(self, state: QuotaState) -> None:
        self._quotas[(state.tenant, state.endpoint)] = state

    def all_quotas(self) -> list[QuotaState]:
        return list(self._quotas.values())
