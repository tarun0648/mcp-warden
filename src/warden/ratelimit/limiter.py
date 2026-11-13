"""Rate limits and daily budgets, decided by one atomic Redis script.

Why one script and not four round trips: a limiter that reads, decides and writes in separate
commands can be beaten by sending many requests at once — each one reads the same "9 tokens
left" and each one allows itself. The whole decision therefore runs inside a single `EVALSHA`,
which Redis executes to completion before it looks at another client.

The script is also *all-or-nothing* across every limit it is given: if the per-tool bucket has
room but the daily budget is spent, nothing is consumed anywhere. That is slightly stricter
than checking each limit in turn, and it means a denied call never leaves a partial charge
behind that the caller cannot see.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Protocol

from warden.config import LimitsConfig, Risk
from warden.logging import get_logger
from warden.ratelimit.clock import Clock, SystemClock, seconds_until_next_utc_midnight, utc_day_key

logger = get_logger(__name__)

KEY_PREFIX: Final = "warden:rl"
BUDGET_PREFIX: Final = "warden:budget"

#: One script decides everything. Written to be read: two passes over the buckets (check, then
#: commit) and two passes over the budgets, so nothing is consumed unless every limit allows it.
LIMITER_SCRIPT: Final = """
-- KEYS: bucket keys, then budget keys.
-- ARGV[1] = now in milliseconds
-- ARGV[2] = number of bucket keys
-- ARGV[3] = number of budget keys
-- then, per bucket: capacity, refill_per_second
-- then, per budget: limit, ttl_seconds
local now_ms = tonumber(ARGV[1])
local bucket_count = tonumber(ARGV[2])
local budget_count = tonumber(ARGV[3])

local new_tokens = {}
local retry_after_ms = 0
local blocked_kind = ''
local blocked_key = ''

-- Pass 1: refill every bucket and check whether all of them have a token.
for i = 1, bucket_count do
  local key = KEYS[i]
  local capacity = tonumber(ARGV[3 + (i - 1) * 2 + 1])
  local rate = tonumber(ARGV[3 + (i - 1) * 2 + 2])
  local state = redis.call('HMGET', key, 'tokens', 'updated_ms')
  local tokens = tonumber(state[1])
  local updated_ms = tonumber(state[2])
  if tokens == nil or updated_ms == nil then
    tokens = capacity
    updated_ms = now_ms
  end
  local elapsed_ms = now_ms - updated_ms
  if elapsed_ms < 0 then elapsed_ms = 0 end
  tokens = math.min(capacity, tokens + (elapsed_ms / 1000.0) * rate)
  new_tokens[i] = tokens
  if tokens < 1 then
    local wait_ms = math.ceil(((1 - tokens) / rate) * 1000)
    if wait_ms > retry_after_ms then
      retry_after_ms = wait_ms
      blocked_kind = 'rate_limit'
      blocked_key = key
    end
  end
end

-- Pass 2: check every budget without incrementing anything.
local budget_offset = 3 + bucket_count * 2
for j = 1, budget_count do
  local key = KEYS[bucket_count + j]
  local limit = tonumber(ARGV[budget_offset + (j - 1) * 2 + 1])
  local ttl = tonumber(ARGV[budget_offset + (j - 1) * 2 + 2])
  local used = tonumber(redis.call('GET', key)) or 0
  if used + 1 > limit then
    if ttl > retry_after_ms / 1000 then
      retry_after_ms = ttl * 1000
    end
    blocked_kind = 'budget'
    blocked_key = key
  end
end

if blocked_kind ~= '' then
  return {0, retry_after_ms, blocked_kind, blocked_key}
end

-- Pass 3: nothing refused, so commit. One token from each bucket, one from each budget.
for i = 1, bucket_count do
  local key = KEYS[i]
  local capacity = tonumber(ARGV[3 + (i - 1) * 2 + 1])
  local rate = tonumber(ARGV[3 + (i - 1) * 2 + 2])
  redis.call('HSET', key, 'tokens', new_tokens[i] - 1, 'updated_ms', now_ms)
  -- Live a little longer than a full refill takes: after that the key is indistinguishable
  -- from a fresh one, so keeping it only wastes memory.
  local ttl = math.ceil(capacity / rate) + 60
  redis.call('EXPIRE', key, ttl)
end

for j = 1, budget_count do
  local key = KEYS[bucket_count + j]
  local ttl = tonumber(ARGV[budget_offset + (j - 1) * 2 + 2])
  redis.call('INCR', key)
  redis.call('EXPIRE', key, ttl)
end

return {1, 0, '', ''}
"""


class LimitKind(StrEnum):
    RATE_LIMIT = "rate_limit"
    BUDGET = "budget"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class LimitDecision:
    """Whether the call may proceed, and if not, when to try again."""

    allowed: bool
    kind: LimitKind | None = None
    retry_after_seconds: float = 0.0
    #: Which limit refused, named for the audit log. Never contains a credential.
    limit: str | None = None
    reason: str = ""


class RedisLike(Protocol):
    """The slice of redis-py the limiter uses."""

    async def eval(self, script: str, numkeys: int, *args: Any) -> Any: ...


def _principal_bucket_key(principal_id: str) -> str:
    return f"{KEY_PREFIX}:p:{principal_id}"


def _tool_bucket_key(principal_id: str, tool: str) -> str:
    return f"{KEY_PREFIX}:pt:{principal_id}:{tool}"


def _budget_key(principal_id: str, day: str) -> str:
    return f"{BUDGET_PREFIX}:calls:{principal_id}:{day}"


def _destructive_budget_key(principal_id: str, day: str) -> str:
    return f"{BUDGET_PREFIX}:destructive:{principal_id}:{day}"


class RateLimiter:
    """Applies the configured buckets and budgets to one call."""

    def __init__(
        self,
        redis: RedisLike,
        limits: LimitsConfig,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._redis = redis
        self._limits = limits
        self._clock = clock or SystemClock()
        if limits.fail_open_when_limiter_down:
            logger.warning(
                "RATE LIMITER IS SET TO FAIL OPEN. This is for local development only: if "
                "Redis goes away, calls will be allowed without any limit."
            )

    async def check(
        self, principal_id: str, roles: tuple[str, ...], tool: str, risk: Risk
    ) -> LimitDecision:
        """Consume one unit from every applicable limit, or refuse and consume nothing."""
        role_limits = self._limits.for_roles(roles)
        now = self._clock.utcnow()
        day = utc_day_key(now)
        ttl = seconds_until_next_utc_midnight(now)

        bucket_keys = [_principal_bucket_key(principal_id), _tool_bucket_key(principal_id, tool)]
        bucket_args: list[Any] = [
            role_limits.per_principal.capacity,
            role_limits.per_principal.refill_per_second,
            role_limits.per_tool.capacity,
            role_limits.per_tool.refill_per_second,
        ]

        budget_keys = [_budget_key(principal_id, day)]
        budget_args: list[Any] = [role_limits.daily_calls, ttl]
        if risk is Risk.DESTRUCTIVE:
            budget_keys.append(_destructive_budget_key(principal_id, day))
            budget_args.extend([role_limits.daily_destructive_calls, ttl])

        keys = bucket_keys + budget_keys
        argv = [
            int(self._clock.now() * 1000),
            len(bucket_keys),
            len(budget_keys),
            *bucket_args,
            *budget_args,
        ]

        try:
            raw = await self._redis.eval(LIMITER_SCRIPT, len(keys), *keys, *argv)
        except Exception as exc:
            return self._unavailable(exc)

        return self._interpret(raw, principal_id)

    def _interpret(self, raw: Any, principal_id: str) -> LimitDecision:
        allowed = bool(_to_int(raw[0]))
        if allowed:
            return LimitDecision(allowed=True)
        retry_after = _to_int(raw[1]) / 1000.0
        kind_text = _to_text(raw[2])
        limit_key = _to_text(raw[3])
        kind = LimitKind.BUDGET if kind_text == "budget" else LimitKind.RATE_LIMIT
        # The key contains the principal id, which is not a secret but is not useful to the
        # caller either; report the limit by name instead.
        named = limit_key.replace(f":{principal_id}", ":<caller>")
        if kind is LimitKind.BUDGET:
            reason = "the daily budget for this caller is spent; it resets at the next UTC midnight"
        else:
            reason = f"too many calls; retry in {retry_after:.1f}s"
        return LimitDecision(
            allowed=False,
            kind=kind,
            retry_after_seconds=retry_after,
            limit=named,
            reason=reason,
        )

    def _unavailable(self, exc: BaseException) -> LimitDecision:
        """Redis is gone. Deny, unless a developer explicitly asked for fail-open."""
        detail = f"{type(exc).__name__}: {exc}"[:200]
        if self._limits.fail_open_when_limiter_down:
            logger.warning(
                "LIMITER UNAVAILABLE, FAILING OPEN - the call is allowed with no limit applied",
                extra={"warden": {"error": detail}},
            )
            return LimitDecision(allowed=True, reason="limiter unavailable, failing open")
        logger.error("limiter unavailable; failing closed", extra={"warden": {"error": detail}})
        return LimitDecision(
            allowed=False,
            kind=LimitKind.UNAVAILABLE,
            retry_after_seconds=1.0,
            limit="limiter",
            reason="the rate limiter is unavailable, so the call cannot be allowed",
        )

    async def usage(self, principal_id: str) -> dict[str, int]:
        """Today's budget counters, for the admin API. Read-only."""
        day = utc_day_key(self._clock.utcnow())
        result: dict[str, int] = {}
        for label, key in (
            ("calls", _budget_key(principal_id, day)),
            ("destructive_calls", _destructive_budget_key(principal_id, day)),
        ):
            try:
                raw = await self._redis.eval("return redis.call('GET', KEYS[1])", 1, key)
            except Exception:
                result[label] = -1
                continue
            result[label] = _to_int(raw) if raw is not None else 0
        return result


def _to_int(value: Any) -> int:
    if isinstance(value, bytes):
        return int(value.decode() or 0)
    if isinstance(value, str):
        return int(value or 0)
    return int(value or 0)


def _to_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


__all__ = [
    "BUDGET_PREFIX",
    "KEY_PREFIX",
    "LIMITER_SCRIPT",
    "LimitDecision",
    "LimitKind",
    "RateLimiter",
]
