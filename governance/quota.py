"""按租户与接口维度的配额限制：总量上限 + 滚动时间窗口。

策略语义：
- 策略按 ``(tenant_id, endpoint)`` 持久化在本地存储中；``tenant_id="*"`` 是
  默认策略，对该 endpoint 下没有精确策略的所有租户生效。策略反复下发（调高/
  调低/覆盖窗口配置）以最后一条为准，进程重启后不丢失、不残留旧策略。
- 一条策略可同时配置两层限制，任一层到顶即拒绝，并能区分被哪一层拦下：
  - 总量层：生命周期累计上限；
  - 窗口层：“每 window_seconds 秒最多 window_limit 次”的滚动窗口，
    窗口随时间自然滑动（ts > now-window_seconds 的事件才计入）。

扣减语义：``acquire`` 的“检查 + 两层计数 + 放行留痕”在存储侧单事务内完成，
只有实际放行的请求才计数（拒绝不计数，无幽灵配额），并发下任何一层都不会被
突破；策略读取或记账链路异常一律上抛 ``QuotaError``，由授权链路拒绝放行
（fail-closed，绝不因链路异常静默放行）。
"""

from __future__ import annotations

from .errors import QuotaError
from .models import AuditRecord, QuotaAcquireResult, QuotaPolicy, QuotaSnapshot
from .storage import DEFAULT_POLICY_TENANT, Storage

DEFAULT_TENANT = DEFAULT_POLICY_TENANT


class QuotaLimiter:
    def __init__(self, storage: Storage, limits: dict[tuple[str, str], int] | None = None) -> None:
        self._storage = storage
        # 兼容旧构造参数：仅总量上限的种子策略（updated_at=0，可被后续下发覆盖）
        for (tenant_id, endpoint), limit in (limits or {}).items():
            self.put_policy(QuotaPolicy(
                tenant_id=tenant_id, endpoint=endpoint, total_limit=limit,
                window_limit=None, window_seconds=None, updated_at=0.0))

    # ---- 策略下发/读取（持久化） ----
    def set_limit(self, tenant_id: str, endpoint: str, limit: int, now: float = 0.0) -> None:
        """兼容旧用法：仅覆盖总量层，保留该维度已有的窗口配置。"""
        self._validate_total_limit(limit)
        existing = None
        try:
            existing = self._storage.get_quota_policy(tenant_id, endpoint)
        except Exception as exc:
            raise QuotaError(f"load quota policy failed: {exc}") from exc
        window_limit = existing.window_limit if existing else None
        window_seconds = existing.window_seconds if existing else None
        self.put_policy(QuotaPolicy(
            tenant_id=tenant_id, endpoint=endpoint, total_limit=limit,
            window_limit=window_limit, window_seconds=window_seconds, updated_at=now))

    def put_policy(self, policy: QuotaPolicy) -> None:
        """下发/调整一条持久化策略（tenant_id="*" 表示默认策略）。"""
        self._validate_policy(policy)
        try:
            self._storage.upsert_quota_policy(policy)
        except Exception as exc:
            raise QuotaError(f"persist quota policy failed: {exc}") from exc

    def effective_policy(self, tenant_id: str, endpoint: str) -> tuple[QuotaPolicy | None, str]:
        """返回生效策略及来源 exact / default / none。"""
        try:
            return self._storage.effective_quota_policy(tenant_id, endpoint)
        except Exception as exc:
            raise QuotaError(f"load quota policy failed: {exc}") from exc

    def limit_for(self, tenant_id: str, endpoint: str) -> int | None:
        """兼容旧用法：返回当前生效策略的总量上限（含默认策略）；无策略为 None。"""
        policy, _ = self.effective_policy(tenant_id, endpoint)
        return policy.total_limit if policy is not None else None

    # ---- 原子判定 ----
    def acquire(self, tenant_id: str, endpoint: str,
                request_id: str, now: float) -> QuotaAcquireResult:
        """原子判定总量层 + 滚动窗口层；链路异常以 QuotaError 上抛（fail-closed）。

        放行的请求在同一存储事务内写 ``access_allowed`` 审计（含命中策略与
        策略来源），用量/上限快照随返回值交给 service 层补进追溯信息。
        """
        policy, source = self.effective_policy(tenant_id, endpoint)
        no_policy_snapshot = QuotaSnapshot(
            total_limit=None, total_used=0, window_limit=None,
            window_seconds=None, window_used=0, policy_source="none")
        if policy is None:
            # 没有精确策略也没有默认策略：该层完全不限（向后兼容旧语义），不计数
            return QuotaAcquireResult(True, "", None, no_policy_snapshot, "none")

        audit_record = AuditRecord(
            seq=0, ts=now, event="access_allowed", request_id=request_id,
            tenant_id=tenant_id, reason="allowed",
            detail=f"policy({policy.tenant_id},{endpoint}) source={source}",
            extra={
                "policy_tenant_id": policy.tenant_id,
                "endpoint": endpoint,
                "policy_source": source,
            },
        )
        def _audit_extra(snapshot: QuotaSnapshot) -> dict:
            # 事务内快照的基础上补策略来源，组装可追溯的完整判定依据
            snap = QuotaSnapshot(
                total_limit=snapshot.total_limit, total_used=snapshot.total_used,
                window_limit=snapshot.window_limit, window_seconds=snapshot.window_seconds,
                window_used=snapshot.window_used, policy_source=source)
            return {
                "policy_tenant_id": policy.tenant_id,
                "endpoint": endpoint,
                "policy_source": source,
                "total_limit": snap.total_limit,
                "total_used": snap.total_used,
                "window_limit": snap.window_limit,
                "window_seconds": snap.window_seconds,
                "window_used": snap.window_used,
                "layer": "",
            }

        try:
            allowed, layer, snapshot = self._storage.acquire_quota(
                tenant_id, policy, now, audit_record=audit_record,
                audit_extra_from_snapshot=_audit_extra)
        except Exception as exc:
            raise QuotaError(f"quota accounting failed: {exc}") from exc
        # 存储层不感知命中的是精确还是默认策略，快照在此处补上来源
        snapshot = QuotaSnapshot(
            total_limit=snapshot.total_limit, total_used=snapshot.total_used,
            window_limit=snapshot.window_limit, window_seconds=snapshot.window_seconds,
            window_used=snapshot.window_used, policy_source=source)
        return QuotaAcquireResult(allowed, layer, policy, snapshot, source)

    def status(self, tenant_id: str, endpoint: str, now: float) -> dict:
        """查询当前真正生效的上限与已用量（含策略来源 exact/default/none）。"""
        policy, source = self.effective_policy(tenant_id, endpoint)
        if policy is None:
            return {"tenant_id": tenant_id, "endpoint": endpoint, "policy_source": "none",
                    "total_limit": None, "total_used": 0,
                    "window_limit": None, "window_seconds": None, "window_used": 0}
        try:
            total_used = self._storage.quota_usage(tenant_id, endpoint)
            window_used = (self._storage.quota_window_usage(
                tenant_id, endpoint, policy.window_seconds, now)
                if policy.has_window() else 0)
        except Exception as exc:
            raise QuotaError(f"read quota status failed: {exc}") from exc
        return {
            "tenant_id": tenant_id, "endpoint": endpoint, "policy_source": source,
            "total_limit": policy.total_limit, "total_used": total_used,
            "window_limit": policy.window_limit if policy.has_window() else None,
            "window_seconds": policy.window_seconds if policy.has_window() else None,
            "window_used": window_used,
            "updated_at": policy.updated_at,
        }

    def try_acquire(self, tenant_id: str, endpoint: str, now: float) -> bool:
        """兼容旧用法：原子检查+扣减（含默认策略与窗口层）。无策略时放行不计数。"""
        result = self.acquire(tenant_id, endpoint, request_id="legacy", now=now)
        return result.allowed

    def usage(self, tenant_id: str, endpoint: str) -> int:
        try:
            return self._storage.quota_usage(tenant_id, endpoint)
        except Exception as exc:
            raise QuotaError(f"read quota usage failed: {exc}") from exc

    # ---- 参数校验（非法策略直接拒绝下发） ----
    @staticmethod
    def _validate_policy(policy: QuotaPolicy) -> None:
        if not policy.tenant_id or not policy.endpoint:
            raise ValueError("tenant_id and endpoint must be non-empty")
        if policy.total_limit is not None:
            QuotaLimiter._validate_total_limit(policy.total_limit)
        has_window = policy.window_limit is not None or (policy.window_seconds or 0) > 0
        if has_window:
            if policy.window_limit is None or policy.window_seconds is None:
                raise ValueError("window_limit and window_seconds must be provided together")
            if policy.window_limit < 1:
                raise ValueError("window_limit must be >= 1")
            if policy.window_seconds <= 0:
                raise ValueError("window_seconds must be > 0")

    @staticmethod
    def _validate_total_limit(limit: int) -> None:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError("total_limit must be a non-negative integer")
