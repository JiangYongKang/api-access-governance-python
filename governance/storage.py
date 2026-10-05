"""本地持久化存储：凭证、配额用量、审计流水（SQLite，线程安全）。"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading

from .models import AuditRecord, Credential, QuotaPolicy, QuotaSnapshot

# 默认策略的租户占位符：对同一 endpoint 下没有精确策略的所有租户生效
DEFAULT_POLICY_TENANT = "*"

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
CREATE TABLE IF NOT EXISTS quota_policies (
    tenant_id      TEXT NOT NULL,
    endpoint       TEXT NOT NULL,
    total_limit    INTEGER,
    window_limit   INTEGER,
    window_seconds REAL,
    updated_at     REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, endpoint)
);
CREATE TABLE IF NOT EXISTS quota_window_events (
    tenant_id TEXT NOT NULL,
    endpoint  TEXT NOT NULL,
    ts        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quota_window_lookup
    ON quota_window_events (tenant_id, endpoint, ts);
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

    所有写操作在单把锁 + 单事务内完成：配额两层（总量/滚动窗口）的“检查 +
    计数 + 放行审计”是原子的（不超扣、无幽灵计数、放行必可追溯），
    策略按 (tenant, endpoint) upsert（反复下发以最后一条为准），
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

    # ---- 配额用量 ----
    def quota_usage(self, tenant_id: str, endpoint: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT used FROM quota_usage WHERE tenant_id=? AND endpoint=?",
                (tenant_id, endpoint),
            ).fetchone()
        return row[0] if row else 0

    # ---- 配额策略（持久化） ----
    def upsert_quota_policy(self, policy: QuotaPolicy) -> None:
        """下发或调整一条策略；同 (tenant, endpoint) 反复下发以最后一条为准。

        INSERT OR REPLACE + updated_at 单调写入：旧策略（无论调高/调低）都不会
        残留生效，重启后读到的就是最后一次下发的内容。
        """
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO quota_policies"
                " (tenant_id, endpoint, total_limit, window_limit, window_seconds, updated_at)"
                " VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(tenant_id, endpoint) DO UPDATE SET"
                " total_limit=excluded.total_limit,"
                " window_limit=excluded.window_limit,"
                " window_seconds=excluded.window_seconds,"
                " updated_at=excluded.updated_at",
                (policy.tenant_id, policy.endpoint, policy.total_limit,
                 policy.window_limit, policy.window_seconds, policy.updated_at),
            )

    def get_quota_policy(self, tenant_id: str, endpoint: str) -> QuotaPolicy | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT tenant_id, endpoint, total_limit, window_limit, window_seconds, updated_at"
                " FROM quota_policies WHERE tenant_id=? AND endpoint=?",
                (tenant_id, endpoint),
            ).fetchone()
        return self._row_to_policy(row)

    def effective_quota_policy(self, tenant_id: str, endpoint: str) -> tuple[QuotaPolicy | None, str]:
        """返回生效策略与来源（exact / default / none）。

        精确策略优先；没有精确策略时回退到该 endpoint 的默认策略（tenant_id="*"）。
        """
        exact = self.get_quota_policy(tenant_id, endpoint)
        if exact is not None:
            return exact, "exact"
        default = self.get_quota_policy(DEFAULT_POLICY_TENANT, endpoint)
        if default is not None:
            return default, "default"
        return None, "none"

    @staticmethod
    def _row_to_policy(row) -> QuotaPolicy | None:
        if row is None:
            return None
        return QuotaPolicy(
            tenant_id=row[0], endpoint=row[1], total_limit=row[2],
            window_limit=row[3], window_seconds=row[4], updated_at=row[5],
        )

    # ---- 配额原子判定（总量 + 滚动窗口，单事务） ----
    def acquire_quota(self, tenant_id: str, policy: QuotaPolicy, now: float,
                      audit_record: AuditRecord | None = None,
                      audit_extra_from_snapshot=None,
                      ) -> tuple[bool, str, QuotaSnapshot]:
        """单事务内完成：总量检查扣减、窗口过期清理与计数。

        策略可以来自精确配置或默认配置（``policy.tenant_id`` 可能为 "*"），
        但用量永远按真实租户 ``tenant_id`` 分桶计数。

        放行才写两类计数，并在同一事务内写放行审计插入；任一层到顶或写入失败则
        计数整体回滚（无幽灵计数、无计数成功却追溯不到的放行）。
        放行时若给了 ``audit_extra_from_snapshot(snapshot)`` 回调，则以其返回的
        dict 作为审计 extra（用于把命中策略时的用量/上限快照一并落盘）。
        返回 (allowed, layer, snapshot)，layer ∈ {"" , total, window}。
        """
        endpoint = policy.endpoint
        has_window = policy.has_window()
        window_seconds = policy.window_seconds if has_window else None
        cutoff = now - window_seconds if has_window else 0.0

        def _snapshot(total_used: int, window_used: int, source: str) -> QuotaSnapshot:
            return QuotaSnapshot(
                total_limit=policy.total_limit,
                total_used=total_used,
                window_limit=policy.window_limit if has_window else None,
                window_seconds=window_seconds,
                window_used=window_used,
                policy_source=source,
            )

        with self._lock, self._conn:
            # 1) 总量层：读当前累计用量
            total_row = self._conn.execute(
                "SELECT used FROM quota_usage WHERE tenant_id=? AND endpoint=?",
                (tenant_id, endpoint),
            ).fetchone()
            total_used = total_row[0] if total_row else 0

            # 2) 窗口层：先清理该维度已滑出窗口的事件，再数窗口内事件
            if has_window:
                self._conn.execute(
                    "DELETE FROM quota_window_events"
                    " WHERE tenant_id=? AND endpoint=? AND ts <= ?",
                    (tenant_id, endpoint, cutoff),
                )
                window_row = self._conn.execute(
                    "SELECT COUNT(*) FROM quota_window_events"
                    " WHERE tenant_id=? AND endpoint=? AND ts > ?",
                    (tenant_id, endpoint, cutoff),
                ).fetchone()
                window_used = window_row[0]
            else:
                window_used = 0

            # 3) 任一层到顶：显式回滚（连过期事件清理也不留下写入），拒绝不计数
            if policy.total_limit is not None and total_used >= policy.total_limit:
                self._conn.rollback()
                return False, "total", _snapshot(total_used, window_used, "")
            if has_window and window_used >= policy.window_limit:
                self._conn.rollback()
                return False, "window", _snapshot(total_used, window_used, "")

            # 4) 放行：总量 +1、窗口插入当前事件；并在同事务写放行审计
            self._conn.execute(
                "INSERT INTO quota_usage (tenant_id, endpoint, used) VALUES (?,?,1)"
                " ON CONFLICT(tenant_id, endpoint) DO UPDATE SET used = used + 1",
                (tenant_id, endpoint),
            )
            if has_window:
                self._conn.execute(
                    "INSERT INTO quota_window_events (tenant_id, endpoint, ts) VALUES (?,?,?)",
                    (tenant_id, endpoint, now),
                )
            if audit_record is not None:
                if audit_extra_from_snapshot is not None:
                    audit_record = dataclasses.replace(
                        audit_record, extra=audit_extra_from_snapshot(
                            _snapshot(total_used + 1, window_used + 1 if has_window else 0, "")))
                self._insert_audit(audit_record)
            return True, "", _snapshot(total_used + 1, window_used + 1 if has_window else 0, "")

    def quota_window_usage(self, tenant_id: str, endpoint: str,
                           window_seconds: float, now: float) -> int:
        """只读查询当前滚动窗口内的已用量（边界 ts > now-window_seconds）。"""
        cutoff = now - window_seconds
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM quota_window_events"
                " WHERE tenant_id=? AND endpoint=? AND ts > ?",
                (tenant_id, endpoint, cutoff),
            ).fetchone()
        return row[0]

    # ---- 审计 ----
    def _insert_audit(self, record: AuditRecord) -> None:
        """在当前事务/连接上插入一条审计（不自行开事务，供组合事务复用）。"""
        self._conn.execute(
            "INSERT INTO audit_log (ts, event, request_id, tenant_id, reason, detail, extra)"
            " VALUES (?,?,?,?,?,?,?)",
            (record.ts, record.event, record.request_id, record.tenant_id,
             record.reason, record.detail, json.dumps(record.extra, sort_keys=True)),
        )

    def append_audit(self, record: AuditRecord) -> None:
        with self._lock, self._conn:
            self._insert_audit(record)

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
