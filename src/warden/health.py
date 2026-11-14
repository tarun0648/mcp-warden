"""Liveness and readiness checks for the gateway's backing services."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from warden.logging import get_logger

logger = get_logger(__name__)

#: A named check: returns None when healthy, or a short reason when not.
Check = Callable[[], Awaitable[str | None]]

DEFAULT_CHECK_TIMEOUT_SECONDS = 3.0


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    """The outcome of every readiness check, and whether the gateway should accept traffic."""

    ready: bool
    checks: dict[str, str]
    """Maps dependency name to "ok" or the reason it is not ready."""


class Readiness:
    """Runs the registered dependency checks concurrently, with a timeout on each."""

    def __init__(self, checks: dict[str, Check], *, timeout: float = DEFAULT_CHECK_TIMEOUT_SECONDS):
        self._checks = checks
        self._timeout = timeout

    async def _run_one(self, name: str, check: Check) -> tuple[str, str]:
        try:
            async with asyncio.timeout(self._timeout):
                problem = await check()
        except TimeoutError:
            return name, f"timed out after {self._timeout:g}s"
        except Exception as exc:
            return name, f"{type(exc).__name__}: {exc}"
        return name, problem or "ok"

    async def check(self) -> ReadinessReport:
        results = await asyncio.gather(
            *(self._run_one(name, check) for name, check in self._checks.items())
        )
        statuses = dict(results)
        return ReadinessReport(
            ready=all(value == "ok" for value in statuses.values()), checks=statuses
        )


def postgres_check(database_url: str) -> Check:
    """A readiness check that opens a connection and runs `SELECT 1`."""

    async def check() -> str | None:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        engine = create_async_engine(database_url, pool_pre_ping=True)
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        finally:
            await engine.dispose()
        return None

    return check


def redis_check(redis_url: str) -> Check:
    """A readiness check that opens a connection and sends PING."""

    async def check() -> str | None:
        import redis.asyncio as aioredis

        # Bounded, so a hung Redis makes readiness report "down" instead of hanging the probe.
        client: aioredis.Redis = aioredis.from_url(
            redis_url, socket_connect_timeout=2.0, socket_timeout=2.0
        )
        try:
            await client.ping()
        finally:
            await client.aclose()
        return None

    return check
