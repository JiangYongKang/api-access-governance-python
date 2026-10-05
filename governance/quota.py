"""按租户×接口维度的配额治理：总量上限 + 滚动时间窗口，两层叠加。

策略解析（确定性）：
1. ``(tenant_id, endpoint)`` 有专属策略 → 整条生效（不与默认策略合并）；
2. 否则查 ``("*", endpoint)`` 默认策略，对所有未单独配置的租户生效；
3. 都没有 → 两层均不限制，但判定仍会写追溯记录。

扣减语义：``acquire`` 的“窗口滚动 → 两层检查 → 计数 → 追溯/审计落盘”
在存储层的单锁单事务内完成，只有实际放行的请求才计数（无幽灵配额），
并发下总量层与窗口层都不会被突破，重启后策略与用量均保持一致。

兼容：旧的 ``set_limit`` / ``try_acquire`` 仍可用，等价于只配置总量层。
"""

from __future__ import annotations

import time

from .errors import PolicyStoreError
from .models import AcquireResult, EffectiveLimits, Policy
from .storage import DEFAULT_TENANT, Storage


class QuotaLimiter:
    def __init__(self, storage: Storage,
                 limits: dict[tuple[str, str], int] | None = None) -> None:
        self._storage = storage
        # 兼容旧构造参数：(tenant, endpoint) -> 总量上限，落盘为仅总量层策略
        for (tenant_id, endpoint), limit in dict(limits or {}).items():
            self.set_limit(tenant_id, endpoint, limit)

    # ---- 策略配置（持久化，覆盖语义） ----
    def set_policy(self, tenant_id: str, endpoint: str,
                   total_limit: int | None, window_seconds: float = 0.0,
                   window_limit: int | None = None, now: float | None = None) -> Policy:
        """整条覆盖下发策略。反复下发以最后一次为准，老策略不会残留。

        total_limit=None 表示总量层不限制；window_limit=None 表示窗口层不限制；
        窗口启用时必须 window_seconds > 0 且 window_limit >= 1。
        """
        self._validate(total_limit, window_seconds, window_limit)
        ts = time.time() if now is None else now
        try:
            self._storage.upsert_policy(tenant_id, endpoint, total_limit,
                                        window_seconds, window_limit, ts)
        except Exception as exc:
            raise PolicyStoreError(f"upsert policy failed: {exc}") from exc
        policy = self._get_policy(tenant_id, endpoint)
        assert policy is not None
        return policy

    def set_limit(self, tenant_id: str, endpoint: str, limit: int) -> None:
        """兼容旧用法：只调整总量上限，保留该维度已有的窗口配置。"""
        existing = self._get_policy(tenant_id, endpoint)
        if existing is not None:
            self.set_policy(tenant_id, endpoint, limit,
                            existing.window_seconds, existing.window_limit)
        else:
            self.set_policy(tenant_id, endpoint, limit)

    def set_window_limit(self, tenant_id: str, endpoint: str,
                         window_seconds: float, window_limit: int) -> None:
        """只调整滚动窗口，保留该维度已有的总量上限。"""
        existing = self._get_policy(tenant_id, endpoint)
        total = existing.total_limit if existing is not None else None
        self.set_policy(tenant_id, endpoint, total, window_seconds, window_limit)

    @staticmethod
    def _validate(total_limit: int | None, window_seconds: float,
                  window_limit: int | None) -> None:
        if total_limit is not None and (not isinstance(total_limit, int) or total_limit < 0):
            raise ValueError("total_limit must be a non-negative int or null")
        if window_limit is not None:
            if not isinstance(window_limit, int) or window_limit < 1:
                raise ValueError("window_limit must be a positive int")
            if window_seconds <= 0:
                raise ValueError("window_seconds must be > 0 when window_limit is set")

    # ---- 策略解析 ----
    def _get_policy(self, tenant_id: str, endpoint: str) -> Policy | None:
        try:
            return self._storage.get_policy(tenant_id, endpoint)
        except Exception as exc:
            raise PolicyStoreError(f"load policy failed: {exc}") from exc

    def effective_limits(self, tenant_id: str, endpoint: str) -> EffectiveLimits:
        """当前真正生效的两层上限：专属策略优先，否则默认策略，否则均不限制。"""
        policy = self._get_policy(tenant_id, endpoint)
        if policy is not None:
            return EffectiveLimits(policy.total_limit, policy.window_seconds,
                                   policy.window_limit, source="tenant")
        default = self._get_policy(DEFAULT_TENANT, endpoint)
        if default is not None:
            return EffectiveLimits(default.total_limit, default.window_seconds,
                                   default.window_limit, source="default")
        return EffectiveLimits(None, 0.0, None, source="none")

    # ---- 双层判定 ----
    def acquire(self, tenant_id: str, endpoint: str, request_id: str,
                now: float) -> AcquireResult:
        """按生效策略做一次原子“检查 + 记账”，并落盘判定追溯。

        策略读取或记账链路异常时抛 PolicyStoreError，调用方必须按拒绝处理。
        """
        eff = self.effective_limits(tenant_id, endpoint)
        trace = {
            "ts": now, "request_id": request_id, "tenant_id": tenant_id,
            "endpoint": endpoint, "reason": "", "detail": "",
        }
        audit = None
        try:
            snapshot = self._storage.acquire_quota_atomic(
                tenant_id, endpoint, eff.total_limit, eff.window_seconds,
                eff.window_limit, eff.source, trace, audit, now,
            )
        except Exception as exc:
            raise PolicyStoreError(f"quota acquire failed: {exc}") from exc
        return AcquireResult(**snapshot)

    def record_denial(self, tenant_id: str, endpoint: str, request_id: str,
                      reason: str, detail: str, now: float,
                      extra: dict | None = None) -> None:
        """凭证/权限类短路拒绝：原子落盘判定追溯 + access_denied 审计。

        链路异常时抛 AuditWriteError（与审计失败同级），调用方必须拒绝。
        """
        from .audit import AuditWriteError

        trace = {
            "ts": now, "request_id": request_id,
            "tenant_id": tenant_id or "-", "endpoint": endpoint,
            "reason": reason, "detail": detail,
        }
        audit = {
            "ts": now, "event": "access_denied", "request_id": request_id,
            "tenant_id": tenant_id or "-", "reason": reason, "detail": detail,
            "extra": extra or {},
        }
        try:
            self._storage.record_decision_atomic(trace, audit)
        except Exception as exc:
            raise AuditWriteError(f"decision record failed: {exc}") from exc

    # ---- 查询 ----
    def usage(self, tenant_id: str, endpoint: str) -> int:
        return self._storage.quota_usage(tenant_id, endpoint)

    def window_usage(self, tenant_id: str, endpoint: str,
                     window_seconds: float, now: float) -> int:
        return self._storage.window_usage(tenant_id, endpoint, window_seconds, now)

    def status(self, tenant_id: str, endpoint: str, now: float) -> dict:
        """当前真正生效的上限与已用量（含策略来源）。"""
        eff = self.effective_limits(tenant_id, endpoint)
        win_used = (self.window_usage(tenant_id, endpoint, eff.window_seconds, now)
                    if eff.window_limit is not None else 0)
        return {
            "tenant_id": tenant_id, "endpoint": endpoint,
            "policy_source": eff.source,
            "total_used": self.usage(tenant_id, endpoint),
            "total_limit": eff.total_limit,
            "window_seconds": eff.window_seconds if eff.window_limit is not None else None,
            "window_used": win_used,
            "window_limit": eff.window_limit,
        }

    def get_decision(self, request_id: str) -> dict | None:
        """按请求标识查判定快照（放行与拒绝均可追溯）。"""
        return self._storage.get_decision(request_id)

    # ---- 兼容旧 API ----
    def limit_for(self, tenant_id: str, endpoint: str) -> int | None:
        return self.effective_limits(tenant_id, endpoint).total_limit

    def try_acquire(self, tenant_id: str, endpoint: str, now: float) -> bool:
        """旧接口：仅按总量层原子检查+扣减（窗口层不在此接口语义内）。"""
        eff = self.effective_limits(tenant_id, endpoint)
        if eff.total_limit is None:
            return True
        return self._storage.try_consume_quota(tenant_id, endpoint,
                                               eff.total_limit, now)
