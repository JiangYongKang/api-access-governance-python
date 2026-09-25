"""按租户与接口维度的配额限制。

扣减语义：try_acquire 是原子的“检查 + 计数”，只有实际放行的请求才计数，
被拒绝的请求不占用配额（无幽灵配额）；用量持久化在本地存储中，重启后保持一致。
"""

from __future__ import annotations

import threading

from .storage import Storage


class QuotaLimiter:
    def __init__(self, storage: Storage, limits: dict[tuple[str, str], int] | None = None) -> None:
        self._storage = storage
        self._limits: dict[tuple[str, str], int] = dict(limits or {})
        self._limits_lock = threading.Lock()

    def set_limit(self, tenant_id: str, endpoint: str, limit: int) -> None:
        with self._limits_lock:
            self._limits[(tenant_id, endpoint)] = limit

    def limit_for(self, tenant_id: str, endpoint: str) -> int | None:
        with self._limits_lock:
            return self._limits.get((tenant_id, endpoint))

    def try_acquire(self, tenant_id: str, endpoint: str, now: float) -> bool:
        """原子检查+扣减。无配置上限时默认放行且不计数。"""
        limit = self.limit_for(tenant_id, endpoint)
        if limit is None:
            return True
        return self._storage.try_consume_quota(tenant_id, endpoint, limit, now)

    def usage(self, tenant_id: str, endpoint: str) -> int:
        return self._storage.quota_usage(tenant_id, endpoint)
