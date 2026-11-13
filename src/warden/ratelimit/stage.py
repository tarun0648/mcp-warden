"""The RateLimit stage, and the output-size check that runs after forwarding."""

from __future__ import annotations

import json

from warden.config import LimitsConfig
from warden.errors import ReasonCode
from warden.logging import get_logger
from warden.pipeline import RequestContext
from warden.proxy.stages import result_size_bytes
from warden.ratelimit.limiter import LimitKind, RateLimiter

logger = get_logger(__name__)


class RateLimit:
    """Apply the caller's buckets and daily budgets, and cap the argument size."""

    name = "ratelimit"

    def __init__(self, limiter: RateLimiter, limits: LimitsConfig) -> None:
        self._limiter = limiter
        self._limits = limits

    async def run(self, ctx: RequestContext) -> None:
        if ctx.principal is None or ctx.tool_name is None:  # pragma: no cover - earlier stages
            ctx.deny(ReasonCode.DENIED_AUTH, "the caller is not authenticated")
            return

        # Cheap local check first: an oversized argument payload is refused without spending a
        # token, and without being measured inside Redis.
        argument_bytes = _argument_size(ctx)
        if argument_bytes > self._limits.max_argument_bytes:
            ctx.deny(
                ReasonCode.DENIED_OUTPUT_TOO_LARGE,
                f"the arguments are {argument_bytes} bytes, over the limit of "
                f"{self._limits.max_argument_bytes}",
            )
            return

        decision = await self._limiter.check(
            ctx.principal.user_id, ctx.principal.roles, ctx.tool_name, ctx.risk
        )
        if decision.allowed:
            return

        reason_code = {
            LimitKind.RATE_LIMIT: ReasonCode.DENIED_RATE_LIMIT,
            LimitKind.BUDGET: ReasonCode.DENIED_BUDGET,
            LimitKind.UNAVAILABLE: ReasonCode.DENIED_LIMITER_UNAVAILABLE,
        }[decision.kind or LimitKind.UNAVAILABLE]
        ctx.scan_flags["retry_after_seconds"] = round(decision.retry_after_seconds, 3)
        if decision.limit:
            ctx.scan_flags["limit"] = decision.limit
        ctx.deny(reason_code, decision.reason)


class OutputLimit:
    """Refuse a result that is too large to hand back.

    It denies rather than truncating: a silently shortened tool result is a correctness bug in
    whatever reads it, and for a model it is worse than an error, because the model cannot tell
    that something is missing.
    """

    name = "output_limit"

    def __init__(self, limits: LimitsConfig) -> None:
        self._limits = limits

    async def run(self, ctx: RequestContext) -> None:
        if ctx.result is None:
            return
        size = ctx.result_bytes or result_size_bytes(ctx.result)
        ctx.result_bytes = size
        if size > self._limits.max_result_bytes:
            logger.warning(
                "upstream result over the size limit",
                extra={
                    "warden": {
                        "tool": ctx.tool_name,
                        "upstream": ctx.upstream,
                        "bytes": size,
                        "limit": self._limits.max_result_bytes,
                    }
                },
            )
            ctx.result = None
            ctx.deny(
                ReasonCode.DENIED_OUTPUT_TOO_LARGE,
                f"the tool returned {size} bytes, over the limit of "
                f"{self._limits.max_result_bytes}; the result was not returned",
            )


def _argument_size(ctx: RequestContext) -> int:
    try:
        return len(json.dumps(ctx.arguments, default=str).encode("utf-8"))
    except (TypeError, ValueError):  # pragma: no cover - arguments come from JSON already
        return 0


__all__ = ["OutputLimit", "RateLimit"]
