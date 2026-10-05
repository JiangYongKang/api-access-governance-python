"""本地持久化存储：凭证、配额策略与用量、滚动窗口、判定追溯、审计流水（SQLite，线程安全）。"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading

from .models import AuditRecord, Credential, Policy

DEFAULT_TENANT = "*"

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
CREATE TABLE IF NOT EXISTS quota_policies (
    tenant_id      TEXT NOT NULL,
    endpoint       TEXT NOT NULL,
    total_limit    INTEGER,
    window_seconds REAL NOT NULL DEFAULT 0,
    window_limit   INTEGER,
    updated_at     REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, endpoint)
);
CREATE TABLE IF NOT EXISTS quota_usage (
    tenant_id TEXT NOT NULL,
    endpoint  TEXT NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, endpoint)
);
CREATE TABLE IF NOT EXISTS quota_window (
    tenant_id TEXT NOT NULL,
    endpoint  TEXT NOT NULL,
    ts        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quota_window_lookup
    ON quota_window (tenant_id, endpoint, ts);
CREATE TABLE IF NOT EXISTS decision_trace (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             REAL NOT NULL,
    request_id     TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    endpoint       TEXT NOT NULL,
    allowed        INTEGER NOT NULL,
    reason         TEXT NOT NULL,
    detail         TEXT NOT NULL,
    layer          TEXT NOT NULL DEFAULT '',
    total_used     INTEGER,
    total_limit    INTEGER,
    window_used    INTEGER,
    window_limit   INTEGER,
    window_seconds REAL,
    policy_source  TEXT NOT NULL DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS idx_decision_trace_request
    ON decision_trace (request_id);
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

    @contextlib.contextmanager
    def transaction(self):
        """单把全局锁 + 单个 SQLite 事务的上下文；with 块内可执行多条原子语句。"""
        with self._lock, self._conn:
            yield self._conn

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

    # ---- 配额策略（持久化） ----
    def upsert_policy(self, tenant_id: str, endpoint: str,
                      total_limit: int | None, window_seconds: float,
                      window_limit: int | None, now: float) -> None:
        """写入/覆盖一条策略（反复下发是覆盖语义，老策略不会残留）。"""
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO quota_policies"
                " (tenant_id, endpoint, total_limit, window_seconds, window_limit, updated_at)"
                " VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(tenant_id, endpoint) DO UPDATE SET"
                " total_limit=excluded.total_limit,"
                " window_seconds=excluded.window_seconds,"
                " window_limit=excluded.window_limit,"
                " updated_at=excluded.updated_at",
                (tenant_id, endpoint, total_limit, window_seconds, window_limit, now),
            )

    def get_policy(self, tenant_id: str, endpoint: str) -> Policy | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT tenant_id, endpoint, total_limit, window_seconds, window_limit, updated_at"
                " FROM quota_policies WHERE tenant_id=? AND endpoint=?",
                (tenant_id, endpoint),
            ).fetchone()
        return self._row_to_policy(row)

    def list_policies(self, endpoint: str | None = None) -> list[Policy]:
        sql = ("SELECT tenant_id, endpoint, total_limit, window_seconds, window_limit, updated_at"
               " FROM quota_policies")
        params: list = []
        if endpoint is not None:
            sql += " WHERE endpoint=?"
            params.append(endpoint)
        sql += " ORDER BY tenant_id, endpoint"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_policy(r) for r in rows]

    @staticmethod
    def _row_to_policy(row: sqlite3.Row | tuple | None) -> Policy | None:
        if row is None:
            return None
        return Policy(
            tenant_id=row[0], endpoint=row[1], total_limit=row[2],
            window_seconds=row[3], window_limit=row[4], updated_at=row[5],
        )

    # ---- 双层判定（总量 + 滚动窗口），全部在单事务内完成 ----
    def acquire_quota_atomic(self, tenant_id: str, endpoint: str,
                             total_limit: int | None, window_seconds: float,
                             window_limit: int | None, policy_source: str,
                             trace: dict, audit: dict | None,
                             now: float) -> dict:
        """原子完成：窗口滚动清理 → 两层检查 → 计数 → 判定追溯/审计落盘。

        - 总量层：quota_usage.used 单调累计，与 total_limit 比较。
        - 窗口层：删除 (now-window_seconds, now] 之外的旧事件后计数，
          与 window_limit 比较；放行时插入一条事件，窗口自然滚动。
        拒绝时不写任何计数；trace（及放行审计）与计数在同一事务内提交，
        因此“未放行却吃掉计数”不可能发生。
        """
        with self._lock, self._conn:
            conn = self._conn
            row = conn.execute(
                "SELECT used FROM quota_usage WHERE tenant_id=? AND endpoint=?",
                (tenant_id, endpoint),
            ).fetchone()
            total_used = row[0] if row else 0

            window_used = 0
            if window_limit is not None:
                conn.execute(
                    "DELETE FROM quota_window WHERE tenant_id=? AND endpoint=?"
                    " AND ts <= ?",
                    (tenant_id, endpoint, now - window_seconds),
                )
                window_used = conn.execute(
                    "SELECT COUNT(*) FROM quota_window WHERE tenant_id=? AND endpoint=?",
                    (tenant_id, endpoint),
                ).fetchone()[0]

            # 判定顺序：先总量层，再窗口层（结论可解释：报告第一个到顶的层）
            layer = ""
            if total_limit is not None and total_used >= total_limit:
                layer = "total"
            elif window_limit is not None and window_used >= window_limit:
                layer = "window"
            allowed = layer == ""

            if allowed:
                if total_limit is not None:
                    conn.execute(
                        "INSERT INTO quota_usage (tenant_id, endpoint, used) VALUES (?,?,1)"
                        " ON CONFLICT(tenant_id, endpoint) DO UPDATE SET used = used + 1",
                        (tenant_id, endpoint),
                    )
                    total_used += 1
                if window_limit is not None:
                    conn.execute(
                        "INSERT INTO quota_window (tenant_id, endpoint, ts) VALUES (?,?,?)",
                        (tenant_id, endpoint, now),
                    )
                    window_used += 1

            reason, detail = self._explain_trace(
                allowed, layer, endpoint, total_used, total_limit, window_used,
                window_seconds, window_limit, policy_source)
            trace = {**trace, "reason": reason, "detail": detail}
            self._insert_trace(conn, trace, allowed, layer, total_used, total_limit,
                               window_used, window_seconds, window_limit, policy_source)
            if audit is not None:
                self._insert_audit(conn, audit)

            return {
                "allowed": allowed, "layer": layer, "reason": reason, "detail": detail,
                "total_used": total_used, "total_limit": total_limit,
                "window_used": window_used,
                "window_seconds": window_seconds, "window_limit": window_limit,
                "policy_source": policy_source,
            }

    def record_decision_atomic(self, trace: dict, audit: dict | None) -> None:
        """凭证/权限类短路拒绝路径：仅原子落盘判定追溯（与审计）。"""
        with self._lock, self._conn:
            conn = self._conn
            self._insert_trace(conn, trace, False, "", None, None, None, 0.0,
                               None, "none")
            if audit is not None:
                self._insert_audit(conn, audit)

    @staticmethod
    def _explain_trace(allowed: bool, layer: str, endpoint: str,
                       total_used: int, total_limit: int | None,
                       window_used: int, window_seconds: float,
                       window_limit: int | None, policy_source: str) -> tuple[str, str]:
        """为追溯记录生成命中的规则与判定依据（人类可读、可解释）。"""
        if allowed:
            allowed_detail = (
                f"source={policy_source} total={total_used}/{total_limit} "
                f"window={window_used}/{window_limit}@{window_seconds:g}s")
            return "allowed", allowed_detail
        label = "total" if layer == "total" else "window"
        reason = "quota_exceeded" if layer == "total" else "rate_limited"
        detail = (f"{label} limit reached for {endpoint}: "
                  f"total={total_used}/{total_limit}, window={window_used}/"
                  f"{window_limit}@{window_seconds:g}s, source={policy_source}")
        return reason, detail

    @staticmethod
    def _insert_trace(conn, trace: dict, allowed: bool, layer: str,
                      total_used: int | None, total_limit: int | None,
                      window_used: int | None, window_seconds: float,
                      window_limit: int | None, policy_source: str) -> None:
        conn.execute(
            "INSERT INTO decision_trace"
            " (ts, request_id, tenant_id, endpoint, allowed, reason, detail,"
            "  layer, total_used, total_limit, window_used, window_limit,"
            "  window_seconds, policy_source)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (trace["ts"], trace["request_id"], trace["tenant_id"], trace["endpoint"],
             int(allowed), trace["reason"], trace["detail"], layer,
             total_used, total_limit, window_used, window_limit,
             window_seconds, policy_source),
        )

    @staticmethod
    def _insert_audit(conn, audit: dict) -> None:
        conn.execute(
            "INSERT INTO audit_log (ts, event, request_id, tenant_id, reason, detail, extra)"
            " VALUES (?,?,?,?,?,?,?)",
            (audit["ts"], audit["event"], audit["request_id"], audit["tenant_id"],
             audit["reason"], audit["detail"],
             json.dumps(audit.get("extra", {}), sort_keys=True)),
        )

    def get_decision(self, request_id: str) -> dict | None:
        """按请求标识查询判定快照（放行/拒绝均可追溯）。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT ts, request_id, tenant_id, endpoint, allowed, reason, detail,"
                " layer, total_used, total_limit, window_used, window_limit,"
                " window_seconds, policy_source"
                " FROM decision_trace WHERE request_id=?",
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "ts": row[0], "request_id": row[1], "tenant_id": row[2], "endpoint": row[3],
            "allowed": bool(row[4]), "reason": row[5], "detail": row[6], "layer": row[7],
            "total_used": row[8], "total_limit": row[9],
            "window_used": row[10], "window_limit": row[11],
            "window_seconds": row[12], "policy_source": row[13],
        }

    def window_usage(self, tenant_id: str, endpoint: str,
                     window_seconds: float, now: float) -> int:
        """查询 (now-window_seconds, now] 滚动窗口内的当前计数（只读，不清理）。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM quota_window WHERE tenant_id=? AND endpoint=?"
                " AND ts > ? AND ts <= ?",
                (tenant_id, endpoint, now - window_seconds, now),
            ).fetchone()
        return row[0]

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
