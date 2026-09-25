"""配额治理：按 (租户, 接口) 维度在固定时间窗口内计数限流。

关键语义:
- 配额只在请求"实际被放行"的同一临界区内预占，被认证/授权拒绝的请求
  永远不会计入，杜绝幽灵配额。
- 窗口为固定窗口（window_start 起 ``window_seconds``），窗口切换时
  计数清零并重置窗口起点，状态随 :class:`GovernanceStore` 持久化，
  重启后沿用同一窗口结论。
- 调用方必须持有 :class:`GovernanceStore` 的锁；配额更新与落盘在同一
  临界区内完成，因此并发请求不可能突破上限。
"""

from __future__ import annotations

import time
from collections.abc import Callable

from governance.errors import DenyReason, GovernanceError
from governance.model import QuotaState
from governance.persistence import GovernanceStore


class QuotaExceeded(Exception):
    """配额耗尽（携带命中规则与当前用量，供编排层转成拒绝结论）。"""

    def __init__(self, state: QuotaState, now: float) -> None:
        self.state = state
        self.now = now
        super().__init__(
            f"quota exceeded for tenant={state.tenant} endpoint={state.endpoint} "
            f"used={state.used} limit={state.limit}"
        )

    def as_governance_error(self) -> GovernanceError:
        return GovernanceError(
            DenyReason.QUOTA_EXCEEDED,
            rule="quota.limit",
            detail=(
                f"租户 {self.state.tenant} 对接口 {self.state.endpoint} 的配额"
                f" {self.state.used}/{self.state.limit} 已用尽"
                f"（窗口起点 {self.state.window_start}，窗口长度 "
                f"{self.state.window_seconds}s，当前 {self.now}）"
            ),
        )


class QuotaManager:
    """按租户与接口维度的配额计数。"""

    def __init__(
        self,
        store: GovernanceStore,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._store = store
        self._clock = clock or time.time

    def _now(self) -> float:
        return self._clock()

    def set_limit(
        self,
        tenant: str,
        endpoint: str,
        limit: int,
        window_seconds: float,
    ) -> QuotaState:
        """设置/更新某维度的配额上限与窗口长度。

        已存在的当前窗口用量保留（窗口起点不变），避免改配置即可绕过
        限流；窗口长度立即生效于下一次滚动判断。
        """
        if limit < 0:
            raise ValueError("limit 不能为负数")
        if window_seconds <= 0:
            raise ValueError("window_seconds 必须为正数")
        with self._store.lock:
            state = self._store.get_quota(tenant, endpoint)
            now = self._now()
            if state is None:
                state = QuotaState(
                    tenant=tenant,
                    endpoint=endpoint,
                    limit=limit,
                    window_seconds=window_seconds,
                    used=0,
                    window_start=now,
                )
            else:
                state.limit = limit
                state.window_seconds = window_seconds
            self._store.put_quota(state)
            self._store.persist()
            return state

    def get_limit(self, tenant: str, endpoint: str) -> tuple[int, float] | None:
        """返回 (上限, 窗口秒数)，未配置返回 None。"""
        state = self._store.get_quota(tenant, endpoint)
        if state is None:
            return None
        return state.limit, state.window_seconds

    def evaluate(self, tenant: str, endpoint: str) -> tuple[QuotaState, bool]:
        """只读评估当前请求能否占用一个配额（不修改存储状态、不落盘）。

        返回 ``(投影状态, 是否可放行)``。投影状态的 ``used`` 为
        *假设放行后*的用量（已做固定窗口滚动与 +1 的纯内存计算）。
        编排层据此先写审计、再 :meth:`commit`，保证审计与配额同时成功
        或同时不发生。调用方必须持有 store 的锁。
        """
        now = self._now()
        state = self._store.get_quota(tenant, endpoint)
        if state is None:
            # 未配置配额 = 无限流。返回非持久化的临时状态用于审计展示。
            return (
                QuotaState(
                    tenant=tenant,
                    endpoint=endpoint,
                    limit=-1,
                    window_seconds=0.0,
                    used=0,
                    window_start=now,
                ),
                True,
            )
        if now >= state.window_start + state.window_seconds:
            # 进入新的固定窗口：投影从零开始，窗口起点对齐当前时刻。
            window_start = now
            base_used = 0
        else:
            window_start = state.window_start
            base_used = state.used
        projected = QuotaState(
            tenant=state.tenant,
            endpoint=state.endpoint,
            limit=state.limit,
            window_seconds=state.window_seconds,
            used=base_used,
            window_start=window_start,
        )
        if base_used >= state.limit:
            return projected, False
        projected.used = base_used + 1
        return projected, True

    def commit(self, projected: QuotaState) -> None:
        """把 :meth:`evaluate` 的投影用量原子地重新演算并落盘。

        重新读取当前状态做一次确定性演算：窗口滚动判定与投影一致且仍有
        余量时才写入，防止并发/时序问题造成超卖。调用方必须持锁。
        """
        current = self._store.get_quota(projected.tenant, projected.endpoint)
        if current is None:
            return  # 未配置限流维度，无状态需要提交。
        now = self._now()
        if now >= current.window_start + current.window_seconds:
            base_used = 0
            window_start = now
        else:
            base_used = current.used
            window_start = current.window_start
        if window_start != projected.window_start:
            raise GovernanceError(
                DenyReason.QUOTA_EXCEEDED,
                rule="quota.commit",
                detail="配额投影窗口与当前窗口脱节，拒绝提交以防超卖",
            )
        if base_used >= current.limit or base_used + 1 != projected.used:
            raise GovernanceError(
                DenyReason.QUOTA_EXCEEDED,
                rule="quota.commit",
                detail=(
                    f"配额提交校验失败 base={base_used} limit={current.limit} "
                    f"projected={projected.used}，拒绝提交以防超卖"
                ),
            )
        current.used = projected.used
        current.window_start = window_start
        self._store.put_quota(current)
        self._store.persist()

    def try_acquire(self, tenant: str, endpoint: str) -> QuotaState:
        """原子地评估并提交一个配额（便捷方法，内部自行加锁）。

        成功返回更新后的 :class:`QuotaState`；配额耗尽抛出
        :class:`QuotaExceeded`，used 不变且不落盘（无幽灵配额）。
        """
        with self._store.lock:
            projected, ok = self.evaluate(tenant, endpoint)
            if not ok:
                state = self._store.get_quota(tenant, endpoint) or projected
                raise QuotaExceeded(state, self._now())
            self.commit(projected)
            return projected

    def usage(self, tenant: str, endpoint: str) -> QuotaState | None:
        """只读查询当前配额状态（不滚动窗口，用于可解释输出）。"""
        return self._store.get_quota(tenant, endpoint)
