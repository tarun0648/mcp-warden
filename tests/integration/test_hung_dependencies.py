"""A dependency that accepts the connection and then stops answering.

"Redis is down" is the easy failure: the connection is refused at once and the limiter's error
path runs. The harder one is a Redis that completes the TCP handshake and then never replies -
a stuck process, a full network buffer, a half-open connection behind a load balancer. The
gateway must turn that into a prompt denial, not a request that waits on a socket.

The locked redis-py happens to default to a 5 s socket timeout; the gateway sets 2 s
explicitly so the bound does not depend on which release is installed. These tests point the
real client, built exactly as the gateway builds it, at a TCP server that accepts and then says
nothing, and require an answer well inside the old default.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from warden.config import LimitsConfig, Risk
from warden.ratelimit.limiter import LimitKind, RateLimiter

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

#: The gateway sets 2 s. Under redis-py's own 5 s default this bound would fail, so passing
#: it shows the gateway's setting is the one in force.
MUST_ANSWER_WITHIN_SECONDS = 4.5


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@asynccontextmanager
async def silent_server() -> AsyncIterator[int]:
    """Accept connections and never write a byte back."""
    held: list[asyncio.StreamWriter] = []

    async def handle(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        held.append(writer)
        await asyncio.sleep(3600)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        for writer in held:
            writer.close()
        server.close()


async def test_a_silent_redis_makes_the_limiter_deny_rather_than_hang(tmp_path: Path) -> None:
    from tests.helpers import test_settings
    from warden.main import build_redis

    async with silent_server() as port:
        settings = test_settings(tmp_path, redis_url=f"redis://127.0.0.1:{port}/0")
        client = build_redis(settings)
        limiter = RateLimiter(client, LimitsConfig())
        started = time.monotonic()
        try:
            decision = await asyncio.wait_for(
                limiter.check("alice", ("editor",), "files__read_file", Risk.READ),
                timeout=MUST_ANSWER_WITHIN_SECONDS + 5,
            )
        finally:
            await client.aclose()
        elapsed = time.monotonic() - started

    assert not decision.allowed, "a hung Redis must deny, never allow"
    assert decision.kind is LimitKind.UNAVAILABLE
    assert elapsed < MUST_ANSWER_WITHIN_SECONDS, f"took {elapsed:.1f}s: the timeout is not applied"


async def test_a_silent_redis_makes_readiness_report_down_promptly() -> None:
    from warden.health import redis_check

    async with silent_server() as port:
        check = redis_check(f"redis://127.0.0.1:{port}/0")
        started = time.monotonic()
        with pytest.raises(Exception):  # noqa: B017 - any failure is the point; a hang is not
            await asyncio.wait_for(check(), timeout=MUST_ANSWER_WITHIN_SECONDS + 5)
        elapsed = time.monotonic() - started
    assert elapsed < MUST_ANSWER_WITHIN_SECONDS, f"took {elapsed:.1f}s"
