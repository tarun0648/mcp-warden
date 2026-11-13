"""Token buckets, daily budgets and size caps, with a fake clock and real Lua in fakeredis."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import fakeredis.aioredis
import pytest

from warden.config import BucketConfig, LimitsConfig, Risk, RoleLimits
from warden.errors import ReasonCode
from warden.pipeline import Decision, Principal, RequestContext
from warden.ratelimit.clock import (
    FakeClock,
    SystemClock,
    seconds_until_next_utc_midnight,
    utc_day_key,
)
from warden.ratelimit.limiter import LimitKind, RateLimiter
from warden.ratelimit.stage import OutputLimit, RateLimit

pytestmark = pytest.mark.unit


def limits(**overrides: Any) -> LimitsConfig:
    defaults: dict[str, Any] = {
        "default": RoleLimits(
            per_principal=BucketConfig(capacity=5, refill_per_second=1.0),
            per_tool=BucketConfig(capacity=3, refill_per_second=0.5),
            daily_calls=10,
            daily_destructive_calls=2,
        )
    }
    defaults.update(overrides)
    return LimitsConfig(**defaults)


@pytest.fixture
def redis() -> Any:
    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(datetime(2026, 11, 13, 12, 0, 0, tzinfo=UTC))


def limiter(redis: Any, clock: FakeClock, **overrides: Any) -> RateLimiter:
    return RateLimiter(redis, limits(**overrides), clock=clock)


# -- the clock ---------------------------------------------------------------------------------


def test_fake_clock_advances() -> None:
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    before = clock.now()
    clock.advance(90)
    assert clock.now() == before + 90
    assert clock.utcnow().minute == 1


def test_system_clock_is_timezone_aware() -> None:
    assert SystemClock().utcnow().tzinfo is UTC


def test_utc_day_key() -> None:
    assert utc_day_key(datetime(2026, 11, 13, 23, 59, tzinfo=UTC)) == "20261113"
    assert utc_day_key(datetime(2026, 11, 14, 0, 0, tzinfo=UTC)) == "20261114"


def test_seconds_until_next_utc_midnight() -> None:
    assert seconds_until_next_utc_midnight(datetime(2026, 11, 13, 23, 59, 0, tzinfo=UTC)) == 60
    assert seconds_until_next_utc_midnight(datetime(2026, 11, 13, 0, 0, 0, tzinfo=UTC)) == 86400
    assert (
        seconds_until_next_utc_midnight(datetime(2026, 11, 13, 23, 59, 59, 999999, tzinfo=UTC)) >= 1
    )


# -- buckets -----------------------------------------------------------------------------------


async def test_a_burst_up_to_capacity_is_allowed_then_refused(redis: Any, clock: FakeClock) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=3, refill_per_second=1.0),
            per_tool=BucketConfig(capacity=99, refill_per_second=99.0),
            daily_calls=100,
            daily_destructive_calls=100,
        ),
    )
    for index in range(3):
        decision = await rl.check("alice", ("reader",), "files__read_file", Risk.READ)
        assert decision.allowed, f"call {index} should have been allowed"
    refused = await rl.check("alice", ("reader",), "files__read_file", Risk.READ)
    assert not refused.allowed
    assert refused.kind is LimitKind.RATE_LIMIT
    assert refused.retry_after_seconds > 0
    assert "<caller>" in (refused.limit or ""), "the limit name must not leak the principal id"


async def test_tokens_refill_as_time_passes(redis: Any, clock: FakeClock) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=2, refill_per_second=1.0),
            per_tool=BucketConfig(capacity=99, refill_per_second=99.0),
            daily_calls=100,
            daily_destructive_calls=100,
        ),
    )
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert not (await rl.check("alice", (), "t", Risk.READ)).allowed

    clock.advance(1.0)
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert not (await rl.check("alice", (), "t", Risk.READ)).allowed

    clock.advance(10.0)
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed


async def test_refill_never_exceeds_capacity(redis: Any, clock: FakeClock) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=2, refill_per_second=1.0),
            per_tool=BucketConfig(capacity=99, refill_per_second=99.0),
            daily_calls=100,
            daily_destructive_calls=100,
        ),
    )
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    clock.advance(10_000)
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert not (await rl.check("alice", (), "t", Risk.READ)).allowed


async def test_callers_are_independent(redis: Any, clock: FakeClock) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=1, refill_per_second=0.1),
            per_tool=BucketConfig(capacity=99, refill_per_second=99.0),
            daily_calls=100,
            daily_destructive_calls=100,
        ),
    )
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert not (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert (await rl.check("bob", (), "t", Risk.READ)).allowed


async def test_the_per_tool_bucket_is_independent_per_tool(redis: Any, clock: FakeClock) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=99, refill_per_second=99.0),
            per_tool=BucketConfig(capacity=1, refill_per_second=0.1),
            daily_calls=100,
            daily_destructive_calls=100,
        ),
    )
    assert (await rl.check("alice", (), "files__read_file", Risk.READ)).allowed
    assert not (await rl.check("alice", (), "files__read_file", Risk.READ)).allowed
    assert (await rl.check("alice", (), "files__write_file", Risk.READ)).allowed


async def test_the_tighter_of_the_two_buckets_wins(redis: Any, clock: FakeClock) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=10, refill_per_second=1.0),
            per_tool=BucketConfig(capacity=2, refill_per_second=0.5),
            daily_calls=100,
            daily_destructive_calls=100,
        ),
    )
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert not (await rl.check("alice", (), "t", Risk.READ)).allowed
    # The principal bucket still has room, so another tool goes through.
    assert (await rl.check("alice", (), "other", Risk.READ)).allowed


async def test_a_refused_call_consumes_nothing(redis: Any, clock: FakeClock) -> None:
    """All-or-nothing: a refusal must not silently charge the buckets that did have room."""
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=10, refill_per_second=1.0),
            per_tool=BucketConfig(capacity=1, refill_per_second=0.001),
            daily_calls=100,
            daily_destructive_calls=100,
        ),
    )
    assert (await rl.check("alice", (), "tight", Risk.READ)).allowed
    for _ in range(5):
        assert not (await rl.check("alice", (), "tight", Risk.READ)).allowed
    # The principal bucket was charged exactly once, so nine calls on another tool remain.
    for index in range(9):
        assert (await rl.check("alice", (), f"other{index}", Risk.READ)).allowed


async def test_role_limits_are_chosen_by_role(redis: Any, clock: FakeClock) -> None:
    config = limits(
        roles={
            "reader": RoleLimits(
                per_principal=BucketConfig(capacity=1, refill_per_second=0.1),
                per_tool=BucketConfig(capacity=99, refill_per_second=99.0),
                daily_calls=100,
                daily_destructive_calls=0,
            ),
            "admin": RoleLimits(
                per_principal=BucketConfig(capacity=50, refill_per_second=10.0),
                per_tool=BucketConfig(capacity=99, refill_per_second=99.0),
                daily_calls=100,
                daily_destructive_calls=100,
            ),
        }
    )
    rl = RateLimiter(redis, config, clock=clock)
    assert (await rl.check("alice", ("reader",), "t", Risk.READ)).allowed
    assert not (await rl.check("alice", ("reader",), "t", Risk.READ)).allowed
    for _ in range(10):
        assert (await rl.check("bob", ("admin",), "t", Risk.READ)).allowed


# -- budgets -----------------------------------------------------------------------------------


async def test_the_daily_budget_is_spent_and_then_refuses(redis: Any, clock: FakeClock) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=100, refill_per_second=100.0),
            per_tool=BucketConfig(capacity=100, refill_per_second=100.0),
            daily_calls=3,
            daily_destructive_calls=100,
        ),
    )
    for _ in range(3):
        assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    refused = await rl.check("alice", (), "t", Risk.READ)
    assert not refused.allowed
    assert refused.kind is LimitKind.BUDGET
    assert "UTC midnight" in refused.reason


async def test_the_budget_resets_at_the_next_utc_midnight(redis: Any, clock: FakeClock) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=100, refill_per_second=100.0),
            per_tool=BucketConfig(capacity=100, refill_per_second=100.0),
            daily_calls=2,
            daily_destructive_calls=100,
        ),
    )
    clock.set(datetime(2026, 11, 13, 23, 59, 0, tzinfo=UTC))
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed
    assert not (await rl.check("alice", (), "t", Risk.READ)).allowed

    clock.set(datetime(2026, 11, 14, 0, 0, 1, tzinfo=UTC))
    assert (await rl.check("alice", (), "t", Risk.READ)).allowed, "a new UTC day is a new budget"


async def test_destructive_calls_have_their_own_smaller_budget(
    redis: Any, clock: FakeClock
) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=100, refill_per_second=100.0),
            per_tool=BucketConfig(capacity=100, refill_per_second=100.0),
            daily_calls=50,
            daily_destructive_calls=2,
        ),
    )
    assert (await rl.check("alice", (), "files__delete_file", Risk.DESTRUCTIVE)).allowed
    assert (await rl.check("alice", (), "files__delete_file", Risk.DESTRUCTIVE)).allowed
    refused = await rl.check("alice", (), "files__delete_file", Risk.DESTRUCTIVE)
    assert not refused.allowed and refused.kind is LimitKind.BUDGET
    # Reads are unaffected: the destructive budget is a separate counter.
    assert (await rl.check("alice", (), "files__read_file", Risk.READ)).allowed


async def test_a_zero_destructive_budget_refuses_the_first_call(
    redis: Any, clock: FakeClock
) -> None:
    """The shipped `reader` role has daily_destructive_calls: 0."""
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=100, refill_per_second=100.0),
            per_tool=BucketConfig(capacity=100, refill_per_second=100.0),
            daily_calls=50,
            daily_destructive_calls=0,
        ),
    )
    refused = await rl.check("alice", (), "files__delete_file", Risk.DESTRUCTIVE)
    assert not refused.allowed and refused.kind is LimitKind.BUDGET


async def test_a_budget_refusal_consumes_no_tokens(redis: Any, clock: FakeClock) -> None:
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=3, refill_per_second=0.001),
            per_tool=BucketConfig(capacity=3, refill_per_second=0.001),
            daily_calls=50,
            daily_destructive_calls=0,
        ),
    )
    for _ in range(5):
        assert not (await rl.check("alice", (), "files__delete_file", Risk.DESTRUCTIVE)).allowed
    # All three tokens are still there, because the budget refused before anything was spent.
    for _ in range(3):
        assert (await rl.check("alice", (), "files__read_file", Risk.READ)).allowed


async def test_usage_reports_todays_counters(redis: Any, clock: FakeClock) -> None:
    rl = limiter(redis, clock)
    await rl.check("alice", (), "t", Risk.READ)
    await rl.check("alice", (), "files__delete_file", Risk.DESTRUCTIVE)
    usage = await rl.usage("alice")
    assert usage == {"calls": 2, "destructive_calls": 1}


async def test_usage_of_an_unknown_caller_is_zero(redis: Any, clock: FakeClock) -> None:
    assert await limiter(redis, clock).usage("nobody") == {"calls": 0, "destructive_calls": 0}


# -- failing closed ----------------------------------------------------------------------------


class BrokenRedis:
    async def eval(self, *_: Any, **__: Any) -> Any:
        raise ConnectionError("redis is down")


async def test_redis_down_denies_by_default(clock: FakeClock) -> None:
    rl = RateLimiter(BrokenRedis(), limits(), clock=clock)
    decision = await rl.check("alice", (), "t", Risk.READ)
    assert not decision.allowed
    assert decision.kind is LimitKind.UNAVAILABLE
    assert "unavailable" in decision.reason


async def test_fail_open_is_opt_in_only(clock: FakeClock) -> None:
    rl = RateLimiter(BrokenRedis(), limits(fail_open_when_limiter_down=True), clock=clock)
    decision = await rl.check("alice", (), "t", Risk.READ)
    assert decision.allowed
    assert "failing open" in decision.reason


async def test_fail_open_logs_a_warning_at_construction(clock: FakeClock) -> None:
    """A gateway running without limits must say so loudly, every time it starts.

    Asserted with a handler attached directly to the limiter's logger rather than with
    `caplog`: the gateway's own `configure_logging` replaces the root handlers, so whether
    caplog's handler is still attached depends on test order.
    """
    import logging

    records: list[logging.LogRecord] = []

    class Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("warden.ratelimit.limiter")
    handler = Collector(level=logging.WARNING)
    logger.addHandler(handler)
    previous = logger.level
    logger.setLevel(logging.WARNING)
    try:
        RateLimiter(BrokenRedis(), limits(fail_open_when_limiter_down=True), clock=clock)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)

    assert any("FAIL OPEN" in record.getMessage() for record in records)


async def test_usage_survives_a_broken_redis(clock: FakeClock) -> None:
    usage = await RateLimiter(BrokenRedis(), limits(), clock=clock).usage("alice")
    assert usage == {"calls": -1, "destructive_calls": -1}


# -- concurrency -------------------------------------------------------------------------------


async def test_concurrent_calls_cannot_exceed_capacity(redis: Any, clock: FakeClock) -> None:
    """The reason the decision is one Lua script: 50 at once must not all read "10 left"."""
    rl = limiter(
        redis,
        clock,
        default=RoleLimits(
            per_principal=BucketConfig(capacity=10, refill_per_second=0.001),
            per_tool=BucketConfig(capacity=100, refill_per_second=0.001),
            daily_calls=1000,
            daily_destructive_calls=1000,
        ),
    )
    results = await asyncio.gather(*(rl.check("alice", (), "t", Risk.READ) for _ in range(50)))
    allowed = sum(1 for decision in results if decision.allowed)
    assert allowed == 10, f"exactly the capacity should pass, got {allowed}"


# -- the stage ---------------------------------------------------------------------------------


def context(**overrides: Any) -> RequestContext:
    defaults: dict[str, Any] = {
        "method": "tools/call",
        "tool_name": "files__read_file",
        "principal": Principal(
            user_id="alice", roles=("reader",), auth_method="api_key", credential_id="pfx"
        ),
        "arguments": {"path": "a.md"},
    }
    defaults.update(overrides)
    return RequestContext(**defaults)


async def test_the_stage_allows_then_denies(redis: Any, clock: FakeClock) -> None:
    config = limits(
        default=RoleLimits(
            per_principal=BucketConfig(capacity=1, refill_per_second=0.01),
            per_tool=BucketConfig(capacity=9, refill_per_second=9.0),
            daily_calls=100,
            daily_destructive_calls=100,
        )
    )
    stage = RateLimit(RateLimiter(redis, config, clock=clock), config)

    first = context()
    await stage.run(first)
    assert first.decision is Decision.ALLOW

    second = context()
    await stage.run(second)
    assert second.reason_code is ReasonCode.DENIED_RATE_LIMIT
    assert second.scan_flags["retry_after_seconds"] > 0
    assert "<caller>" in second.scan_flags["limit"]


async def test_the_stage_reports_a_budget_denial_distinctly(redis: Any, clock: FakeClock) -> None:
    config = limits(
        default=RoleLimits(
            per_principal=BucketConfig(capacity=99, refill_per_second=99.0),
            per_tool=BucketConfig(capacity=99, refill_per_second=99.0),
            daily_calls=99,
            daily_destructive_calls=0,
        )
    )
    stage = RateLimit(RateLimiter(redis, config, clock=clock), config)
    ctx = context(risk=Risk.DESTRUCTIVE, tool_name="files__delete_file")
    await stage.run(ctx)
    assert ctx.reason_code is ReasonCode.DENIED_BUDGET


async def test_the_stage_denies_when_the_limiter_is_down(clock: FakeClock) -> None:
    config = limits()
    stage = RateLimit(RateLimiter(BrokenRedis(), config, clock=clock), config)
    ctx = context()
    await stage.run(ctx)
    assert ctx.reason_code is ReasonCode.DENIED_LIMITER_UNAVAILABLE


async def test_the_stage_refuses_oversized_arguments_without_touching_redis(
    clock: FakeClock,
) -> None:
    """Checked locally, so a giant payload costs no token and is never measured in Redis."""
    config = limits(max_argument_bytes=1024)
    stage = RateLimit(RateLimiter(BrokenRedis(), config, clock=clock), config)
    ctx = context(arguments={"content": "x" * 5000})
    await stage.run(ctx)
    assert ctx.reason_code is ReasonCode.DENIED_OUTPUT_TOO_LARGE
    assert "arguments are" in (ctx.reason or "")


async def test_the_stage_denies_an_unauthenticated_request(redis: Any, clock: FakeClock) -> None:
    config = limits()
    stage = RateLimit(RateLimiter(redis, config, clock=clock), config)
    ctx = context(principal=None)
    await stage.run(ctx)
    assert ctx.reason_code is ReasonCode.DENIED_AUTH


# -- output size -------------------------------------------------------------------------------


async def test_output_over_the_limit_is_denied_not_truncated() -> None:
    from mcp_types import CallToolResult, TextContent

    config = limits(max_result_bytes=1024)
    ctx = context()
    ctx.result = CallToolResult(content=[TextContent(type="text", text="A" * 2048)])
    await OutputLimit(config).run(ctx)
    assert ctx.reason_code is ReasonCode.DENIED_OUTPUT_TOO_LARGE
    assert ctx.result is None, "a too-large result must not be returned in any form"
    assert "2048 bytes" in (ctx.reason or "")


async def test_output_within_the_limit_passes_through() -> None:
    from mcp_types import CallToolResult, TextContent

    config = limits(max_result_bytes=1024)
    ctx = context()
    ctx.result = CallToolResult(content=[TextContent(type="text", text="A" * 100)])
    await OutputLimit(config).run(ctx)
    assert ctx.decision is Decision.ALLOW
    assert ctx.result is not None
    assert ctx.result_bytes == 100


async def test_output_limit_ignores_a_request_with_no_result() -> None:
    ctx = context()
    await OutputLimit(limits()).run(ctx)
    assert ctx.decision is Decision.ALLOW
