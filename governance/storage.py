"""本地持久化存储：凭证、配额用量、审计流水（SQLite，线程安全）。"""

from __future__ import annotations

import json
import sqlite3
import threading

from .models import AuditRecord, Credential

_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    key_id      TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL,
    secret      TEXT NOT NULL,
    issued_at   REAL NOT NULL,
    expires_at  REAL NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    grace_until REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS quota_usage (
    tenant_id TEXT NOT NULL,
    endpoint  TEXT NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, endpoint)
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    event      TEXT NOT NULL,
    request_id TEXT NOT NULL,
    tenant_id  TEXT NOT NULL,
    reason     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    extra      TEXT NOT NULL DEFAULT '{}'
);
"""


class Storage:
    """基于 SQLite 的本地状态存储。

    所有写操作在单把锁 + 单事务内完成：配额扣减是原子的（不超扣、无幽灵计数），
    审计追加在事务内提交（不丢失、不重复）。使用文件路径时重启后状态保留。
    """

    def __init__(self, path: str = ":memory:") -> None:
        self._path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)

    # ---- 凭证 ----
    def save_credential(self, cred: Credential) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO credentials"
                " (key_id, tenant_id, scopes, secret, issued_at, expires_at, revoked, grace_until)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (cred.key_id, cred.tenant_id, json.dumps(sorted(cred.scopes)), cred.secret,
                 cred.issued_at, cred.expires_at, int(cred.revoked), cred.grace_until),
            )

    def get_credential(self, key_id: str) -> Credential | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT key_id, tenant_id, scopes, secret, issued_at, expires_at, revoked, grace_until"
                " FROM credentials WHERE key_id = ?", (key_id,),
            ).fetchone()
        if row is None:
            return None
        return Credential(
            key_id=row[0], tenant_id=row[1], scopes=frozenset(json.loads(row[2])),
            secret=row[3], issued_at=row[4], expires_at=row[5],
            revoked=bool(row[6]), grace_until=row[7],
        )

    # ---- 配额 ----
    def try_consume_quota(self, tenant_id: str, endpoint: str, limit: int, now: float) -> bool:
        """原子地检查并扣减一次配额；放行才计数，拒绝不计数（无幽灵配额）。"""
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT used FROM quota_usage WHERE tenant_id=? AND endpoint=?",
                (tenant_id, endpoint),
            ).fetchone()
            used = row[0] if row else 0
            if used >= limit:
                return False
            self._conn.execute(
                "INSERT INTO quota_usage (tenant_id, endpoint, used) VALUES (?,?,1)"
                " ON CONFLICT(tenant_id, endpoint) DO UPDATE SET used = used + 1",
                (tenant_id, endpoint),
            )
            return True

    def quota_usage(self, tenant_id: str, endpoint: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT used FROM quota_usage WHERE tenant_id=? AND endpoint=?",
                (tenant_id, endpoint),
            ).fetchone()
        return row[0] if row else 0

    # ---- 审计 ----
    def append_audit(self, record: AuditRecord) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO audit_log (ts, event, request_id, tenant_id, reason, detail, extra)"
                " VALUES (?,?,?,?,?,?,?)",
                (record.ts, record.event, record.request_id, record.tenant_id,
                 record.reason, record.detail, json.dumps(record.extra, sort_keys=True)),
            )

    def query_audit(self, tenant_id: str | None = None, event: str | None = None) -> list[AuditRecord]:
        sql = "SELECT seq, ts, event, request_id, tenant_id, reason, detail, extra FROM audit_log"
        clauses, params = [], []
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if event is not None:
            clauses.append("event = ?")
            params.append(event)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [
            AuditRecord(seq=r[0], ts=r[1], event=r[2], request_id=r[3], tenant_id=r[4],
                        reason=r[5], detail=r[6], extra=json.loads(r[7]))
            for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
