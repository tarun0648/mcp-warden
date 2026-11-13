"""Abuse limits through the real gateway, plus the atomicity test against a real Redis."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import requires_redis
from tests.helpers import (
    approve_tool,
    error_text,
    gateway_client,
    payload,
    policies_allowing,
    running_gateway,
)

pytestmark = pytest.mark.integration

TIGHT_LIMITS: dict[str, Any] = {
    "limits": {
        "default": {
            "per_principal": {"capacity": 3, "refill_per_second": 0.01},
            "per_tool": {"capacity": 99, "refill_per_second": 99.0},
            "daily_calls": 1000,
            "daily_destructive_calls": 1000,
        },
        "roles": {},
    }
}


async def test_a_burst_past_the_bucket_is_denied(tmp_path: Path) -> None:
    with running_gateway(tmp_path, gateway_overrides=TIGHT_LIMITS) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            outcomes = [
                await client.call_tool("notes_db__list_notes", {"limit": 1}) for _ in range(5)
            ]
    allowed = [result for result in outcomes if not result.is_error]
    denied = [result for result in outcomes if result.is_error]
    assert len(allowed) == 3, f"expected exactly the capacity to pass, got {len(allowed)}"
    assert denied
    for result in denied:
        assert "WARDEN_DENIED:rate_limit" in error_text(result)
        assert result.structured_content is not None
        assert result.structured_content["error"] == "WARDEN_DENIED:rate_limit"


async def test_a_denied_call_never_reaches_the_upstream(tmp_path: Path) -> None:
    """Proof by side effect: the writes that got through are the only files on disk."""
    with running_gateway(tmp_path, gateway_overrides=TIGHT_LIMITS) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            for index in range(6):
                await client.call_tool(
                    "files__write_file", {"path": f"f{index}.md", "content": "x"}
                )
    written = sorted(p.name for p in (tmp_path / "sandbox").iterdir())
    assert len(written) == 3, f"only the allowed calls should have written: {written}"


async def test_the_daily_destructive_budget_is_separate(tmp_path: Path) -> None:
    overrides: dict[str, Any] = {
        "limits": {
            "default": {
                "per_principal": {"capacity": 99, "refill_per_second": 99.0},
                "per_tool": {"capacity": 99, "refill_per_second": 99.0},
                "daily_calls": 99,
                "daily_destructive_calls": 1,
            },
            "roles": {},
        }
    }
    # Prepended: the shipped `editor-files-delete` rule matches first otherwise, and it
    # leaves approval on, so the call would wait for a human instead of hitting the budget.
    policies = policies_allowing(
        "editor",
        "editor-delete-no-approval",
        ["files__delete_file"],
        prepend=True,
        require_approval=False,
    )
    with running_gateway(
        tmp_path, gateway_overrides=overrides, policies_config=policies
    ) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            for name in ("a.md", "b.md"):
                payload(await client.call_tool("files__write_file", {"path": name, "content": "x"}))
            first = await client.call_tool("files__delete_file", {"path": "a.md"})
            second = await client.call_tool("files__delete_file", {"path": "b.md"})
            # Reads are untouched by the destructive budget.
            read = await client.call_tool("files__list_files", {"path": "."})

    assert not first.is_error, error_text(first) if first.is_error else ""
    assert "WARDEN_DENIED:budget" in error_text(second)
    assert not read.is_error
    assert not (tmp_path / "sandbox" / "a.md").exists()
    assert (tmp_path / "sandbox" / "b.md").exists(), "the budget-denied delete must not have run"


async def test_an_oversized_result_is_denied_not_truncated(tmp_path: Path) -> None:
    overrides: dict[str, Any] = {"limits": {"max_result_bytes": 65536}}
    policies = policies_allowing("redteam", "redteam-evil-huge", ["evil__*"])
    with running_gateway(
        tmp_path,
        include_evil=True,
        gateway_overrides=overrides,
        policies_config=policies,
        evil_timeout=10.0,
    ) as gateway:
        approve_tool(gateway, "evil__huge_output")
        async with gateway_client(gateway, gateway.auth("redteam")) as client:
            too_big = await client.call_tool("evil__huge_output", {"kb": 1024})
            just_right = await client.call_tool("evil__huge_output", {"kb": 32})
    assert "WARDEN_DENIED:output_too_large" in error_text(too_big)
    assert "1048576 bytes" in error_text(too_big)
    assert not just_right.is_error, "a result inside the limit must still come through"


async def test_an_oversized_argument_payload_is_denied(tmp_path: Path) -> None:
    overrides: dict[str, Any] = {"limits": {"max_argument_bytes": 2048}}
    with running_gateway(tmp_path, gateway_overrides=overrides) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool(
                "files__write_file", {"path": "big.md", "content": "x" * 10_000}
            )
    assert "WARDEN_DENIED:output_too_large" in error_text(result)
    assert not (tmp_path / "sandbox" / "big.md").exists()


async def test_the_limiter_being_down_denies_every_call(tmp_path: Path) -> None:
    """Hard rule 1: no Redis means no decision, and no decision means no call."""

    class BrokenRedis:
        async def eval(self, *_: Any, **__: Any) -> Any:
            raise ConnectionError("redis is down")

        async def exists(self, *_: Any) -> int:
            raise ConnectionError("redis is down")

        async def set(self, *_: Any, **__: Any) -> None:
            raise ConnectionError("redis is down")

    with running_gateway(tmp_path, redis=BrokenRedis()) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            result = await client.call_tool("notes_db__list_notes", {"limit": 1})
            # Listing still works: it does not consume a limit.
            listing = await client.list_tools()
    assert "WARDEN_DENIED:limiter_unavailable" in error_text(result)
    assert listing.tools, "tools/list must still answer when only the limiter is down"


async def test_normal_traffic_is_not_limited_by_the_shipped_defaults(tmp_path: Path) -> None:
    """The no-false-positive partner: twenty ordinary reads must all succeed."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            results = await asyncio.gather(
                *(client.call_tool("notes_db__get_note", {"note_id": 1}) for _ in range(20))
            )
    assert all(not result.is_error for result in results), [
        error_text(r) for r in results if r.is_error
    ]


@requires_redis
async def test_fifty_concurrent_calls_against_real_redis_allow_exactly_the_capacity(
    tmp_path: Path,
) -> None:
    """The atomicity claim, against the real server rather than fakeredis."""
    import redis.asyncio as aioredis

    from warden.config import BucketConfig, LimitsConfig, RoleLimits
    from warden.ratelimit.limiter import RateLimiter

    client: aioredis.Redis = aioredis.from_url("redis://localhost:6379/15")
    try:
        await client.flushdb()
        limits = LimitsConfig(
            default=RoleLimits(
                per_principal=BucketConfig(capacity=10, refill_per_second=0.001),
                per_tool=BucketConfig(capacity=100, refill_per_second=0.001),
                daily_calls=1000,
                daily_destructive_calls=1000,
            )
        )
        limiter = RateLimiter(client, limits)
        from warden.config import Risk

        results = await asyncio.gather(
            *(limiter.check("alice", (), "t", Risk.READ) for _ in range(50))
        )
        allowed = sum(1 for decision in results if decision.allowed)
        assert allowed == 10, f"exactly 10 of 50 should pass, got {allowed}"
    finally:
        await client.flushdb()
        await client.aclose()


@requires_redis
async def test_the_budget_counter_expires_at_the_next_utc_midnight(tmp_path: Path) -> None:
    import redis.asyncio as aioredis

    from warden.config import LimitsConfig, Risk
    from warden.ratelimit.clock import SystemClock, seconds_until_next_utc_midnight
    from warden.ratelimit.limiter import RateLimiter

    client: aioredis.Redis = aioredis.from_url("redis://localhost:6379/15")
    try:
        await client.flushdb()
        limiter = RateLimiter(client, LimitsConfig())
        await limiter.check("alice", (), "t", Risk.READ)
        keys = [key async for key in client.scan_iter("warden:budget:calls:alice:*")]
        assert keys, "a budget counter should exist"
        ttl = await client.ttl(keys[0])
        expected = seconds_until_next_utc_midnight(SystemClock().utcnow())
        assert 0 < ttl <= expected + 2
    finally:
        await client.flushdb()
        await client.aclose()
