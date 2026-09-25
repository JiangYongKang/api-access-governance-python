"""测试辅助工具：可控时钟与判定日志。"""

from __future__ import annotations

import logging


class MutableClock:
    """可在测试中拨弄的时钟，保证时序相关结论可复现。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


logger = logging.getLogger("test.governance")


def log_decision(rid: str, stage: str, **fields: object) -> None:
    """统一打印请求标识、命中规则与判定依据，满足可复现/可解释要求。"""
    extra = " ".join(f"{k}={v}" for k, v in fields.items())
    logger.info("request_id=%s stage=%s %s", rid, stage, extra)
