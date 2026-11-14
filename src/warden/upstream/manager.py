"""Connections to the upstream MCP servers.

Each upstream gets one dedicated owner task that enters the SDK client, keeps it alive, and
reconnects with exponential backoff when it drops. The owner task exists because the SDK's
client is an anyio context manager: entering it in one task and leaving it in another is a
"cancel scope in a different task" error, so one task owns the whole lifetime and request
handlers only ever *use* the session it publishes.

One upstream being down never blocks another: every connection has its own task, its own
backoff and its own health state.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import random
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from mcp import Client, StdioServerParameters
from mcp_types import CallToolResult, Tool

from warden.config import HttpTransport, ServersConfig, StdioTransport, UpstreamConfig
from warden.logging import get_logger

logger = get_logger(__name__)

#: Variables copied from the gateway's own environment into every stdio upstream it spawns.
#:
#: The MCP SDK deliberately gives a child process almost nothing (PATH, HOME and a few more),
#: so the gateway's DATABASE_URL, Redis URL and signing-key paths never reach an upstream -
#: including an untrusted one. That property is kept: this list is names, not a prefix, and
#: each is a setting of the `uv` launcher that `servers.yaml` uses as its command, none of them
#: secret. A prefix like `UV_*` would also forward `UV_INDEX_URL`, which can carry a private
#: index's credentials. Anything an upstream itself needs goes in its `env:` in servers.yaml.
LAUNCHER_ENV_VARS: tuple[str, ...] = (
    "UV_NO_SYNC",
    "UV_FROZEN",
    "UV_OFFLINE",
    "UV_CACHE_DIR",
    "UV_PROJECT_ENVIRONMENT",
    "UV_PYTHON_DOWNLOADS",
)

INITIAL_BACKOFF_SECONDS = 0.5
MAX_BACKOFF_SECONDS = 30.0


class UpstreamState(StrEnum):
    STARTING = "starting"
    UP = "up"
    DOWN = "down"
    STOPPED = "stopped"


class UpstreamUnavailable(RuntimeError):
    """The upstream is not connected right now."""


@dataclass(slots=True)
class UpstreamHealth:
    """What the admin API and /metrics report about one upstream."""

    name: str
    state: UpstreamState = UpstreamState.STARTING
    last_error: str | None = None
    connected_at: float | None = None
    tool_count: int = 0
    consecutive_failures: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": str(self.state),
            "last_error": self.last_error,
            "tool_count": self.tool_count,
            "connected_at": self.connected_at,
        }


def _signature(tools: tuple[Tool, ...]) -> str:
    """A stable fingerprint of a tool listing, used to notice that definitions changed."""
    return hashlib.sha256(
        json.dumps(
            [tool.model_dump(mode="json", by_alias=True) for tool in tools],
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def stdio_env(transport: StdioTransport) -> dict[str, str]:
    """The extra environment for a stdio upstream: launcher settings, then its own `env:`.

    The upstream's own entries win, so servers.yaml can always override a forwarded value.
    """
    env = {name: os.environ[name] for name in LAUNCHER_ENV_VARS if name in os.environ}
    env.update(transport.env)
    return env


def _client_for(config: UpstreamConfig) -> Client:
    """Build an SDK client for an upstream's transport."""
    transport = config.transport
    if isinstance(transport, StdioTransport):
        return Client(
            StdioServerParameters(
                command=transport.command,
                args=list(transport.args),
                env=stdio_env(transport) or None,
                cwd=transport.cwd,
            ),
            read_timeout_seconds=config.timeout_seconds,
            # The gateway rebuilds the listing itself; a cached one would hide a rug pull.
            cache=None,
        )
    if isinstance(transport, HttpTransport):
        return Client(transport.url, read_timeout_seconds=config.timeout_seconds, cache=None)
    raise TypeError(f"unsupported transport {transport!r}")  # pragma: no cover


class UpstreamConnection:
    """One upstream: its owner task, its session, its tools and its health."""

    def __init__(
        self,
        config: UpstreamConfig,
        *,
        connect_timeout: float = 10.0,
        health_interval: float = 5.0,
        client_factory: Any | None = None,
    ) -> None:
        self.config = config
        self.health = UpstreamHealth(name=config.name)
        self._connect_timeout = connect_timeout
        self._health_interval = health_interval
        self._client_factory = client_factory or _client_for
        self._client: Client | None = None
        self._tools: tuple[Tool, ...] = ()
        self._signature: str = ""
        #: Set by the manager: called when this upstream's definitions change under us.
        self.on_tools_changed: Any | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._reconnect = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._semaphore = asyncio.Semaphore(config.max_concurrency)

    # -- lifecycle ----------------------------------------------------------------------

    def start(self) -> None:
        """Start the owner task. Returns immediately; use `wait_ready` to block on first connect."""
        if self._task is None:
            self._task = asyncio.create_task(self._own(), name=f"upstream:{self.config.name}")

    async def wait_ready(self, timeout: float) -> bool:
        """Wait until the first connection attempt has succeeded, or `timeout` elapses."""
        try:
            async with asyncio.timeout(timeout):
                await self._ready.wait()
        except TimeoutError:
            return False
        return True

    async def stop(self) -> None:
        """Ask the owner task to disconnect and wait for it."""
        self._stop.set()
        self._reconnect.set()
        if self._task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        self.health.state = UpstreamState.STOPPED

    async def _own(self) -> None:
        """Connect, publish the session, hold it, and reconnect on failure."""
        backoff = INITIAL_BACKOFF_SECONDS
        while not self._stop.is_set():
            self._reconnect.clear()
            try:
                client = self._client_factory(self.config)
                async with asyncio.timeout(self._connect_timeout):
                    await client.__aenter__()
            except Exception as exc:
                self._record_down(exc)
                if self._stop.is_set():
                    break
                await self._sleep_with_jitter(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
                continue

            backoff = INITIAL_BACKOFF_SECONDS
            self._client = client
            try:
                await self._refresh_tools()
                self.health.state = UpstreamState.UP
                self.health.last_error = None
                self.health.connected_at = time.time()
                self.health.consecutive_failures = 0
                self._ready.set()
                logger.info(
                    "upstream connected",
                    extra={
                        "warden": {
                            "upstream": self.config.name,
                            "tools": self.health.tool_count,
                        }
                    },
                )
                await self._hold()
            except Exception as exc:
                self._record_down(exc)
            finally:
                self._client = None
                with contextlib.suppress(Exception):
                    await client.__aexit__(None, None, None)
            if self._stop.is_set():
                break
            await self._sleep_with_jitter(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
        self.health.state = UpstreamState.STOPPED

    async def _hold(self) -> None:
        """Stay connected, re-listing tools periodically, until stop or a failed probe.

        The liveness probe is `tools/list`, not `ping`: ping was removed from the protocol in
        2026-07-28, so pinging a modern upstream answers "method not found" and would mark every
        healthy server down. Re-listing is the probe *and* the refresh, which is also how a rug
        pull gets noticed promptly.
        """
        while not self._stop.is_set() and not self._reconnect.is_set():
            try:
                async with asyncio.timeout(self._health_interval):
                    await self._reconnect.wait()
                return
            except TimeoutError:
                pass
            if self._stop.is_set():
                return
            if self._client is None:  # pragma: no cover - only on a torn-down connection
                return
            try:
                changed = await self._refresh_tools()
            except Exception as exc:
                self._record_down(exc)
                return
            if changed:
                await self._notify_change()

    async def _notify_change(self) -> None:
        if self.on_tools_changed is None:
            return
        outcome = self.on_tools_changed()
        if asyncio.iscoroutine(outcome):
            await outcome

    def _record_down(self, exc: BaseException) -> None:
        self.health.state = UpstreamState.DOWN
        self.health.last_error = f"{type(exc).__name__}: {exc}"[:500]
        self.health.consecutive_failures += 1
        self.health.tool_count = 0
        self._tools = ()
        self._signature = ""
        self._ready.clear()
        logger.warning(
            "upstream unavailable",
            extra={
                "warden": {
                    "upstream": self.config.name,
                    "error": self.health.last_error,
                    "failures": self.health.consecutive_failures,
                }
            },
        )

    async def _sleep_with_jitter(self, seconds: float) -> None:
        """Back off, but return at once if we are shutting down."""
        # Jitter, so a fleet of gateways does not reconnect in lockstep. Not a secret and not
        # a security decision, so the standard PRNG is the right tool.
        delay = seconds * (0.5 + random.random())  # nosec B311
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(delay):
                await self._stop.wait()

    # -- use ----------------------------------------------------------------------------

    @property
    def is_up(self) -> bool:
        return self.health.state is UpstreamState.UP and self._client is not None

    @property
    def tools(self) -> tuple[Tool, ...]:
        """The tool definitions as last fetched. Empty while the upstream is down."""
        return self._tools

    async def _refresh_tools(self) -> bool:
        """Re-fetch the tool list. Returns True when the definitions changed."""
        client = self._client
        if client is None:
            raise UpstreamUnavailable(f"{self.config.name} is not connected")
        async with asyncio.timeout(self.config.timeout_seconds):
            listing = await client.list_tools(cache_mode="bypass")
        fresh = tuple(listing.tools)
        signature = _signature(fresh)
        changed = signature != self._signature
        self._tools = fresh
        self._signature = signature
        self.health.tool_count = len(fresh)
        return changed

    async def refresh_tools(self) -> tuple[Tool, ...]:
        """Re-fetch the tool list. Marks the upstream down if the fetch fails."""
        try:
            await self._refresh_tools()
        except Exception as exc:
            self._record_down(exc)
            self._reconnect.set()
            raise
        return self._tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        """Call one of this upstream's tools, under its timeout and concurrency cap.

        A transport failure marks the upstream down and schedules a reconnect, so the next
        `tools/list` stops advertising its tools instead of handing out names that cannot work.
        """
        client = self._client
        if client is None or not self.is_up:
            raise UpstreamUnavailable(f"{self.config.name} is not connected")
        async with self._semaphore:
            try:
                async with asyncio.timeout(self.config.timeout_seconds):
                    return await client.call_tool(name, arguments)
            except TimeoutError:
                raise
            except Exception as exc:
                self._record_down(exc)
                self._reconnect.set()
                raise


class UpstreamManager:
    """Owns every upstream connection and answers "what tools exist right now?"."""

    def __init__(
        self,
        config: ServersConfig,
        *,
        connect_timeout: float = 10.0,
        health_interval: float = 5.0,
        refresh_interval: float = 300.0,
        client_factory: Any | None = None,
    ) -> None:
        self.config = config
        self._refresh_interval = refresh_interval
        self.connections: dict[str, UpstreamConnection] = {
            upstream.name: UpstreamConnection(
                upstream,
                connect_timeout=connect_timeout,
                health_interval=health_interval,
                client_factory=client_factory,
            )
            for upstream in config.enabled
        }
        for connection in self.connections.values():
            connection.on_tools_changed = self._notify_tools_changed
        self._refresh_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        #: Called after every successful tool refresh, so the registry and the pin store can
        #: re-scan definitions. Set by the proxy.
        self.on_tools_changed: Any | None = None

    async def start(self, *, wait_seconds: float = 0.0) -> None:
        """Start every connection. With `wait_seconds` > 0, wait that long for first connects."""
        for connection in self.connections.values():
            connection.start()
        if wait_seconds > 0:
            await asyncio.gather(
                *(c.wait_ready(wait_seconds) for c in self.connections.values()),
                return_exceptions=True,
            )
        self._refresh_task = asyncio.create_task(self._refresh_loop(), name="upstream:refresh")
        await self._notify_tools_changed()

    async def stop(self) -> None:
        self._stop.set()
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._refresh_task
            self._refresh_task = None
        await asyncio.gather(*(c.stop() for c in self.connections.values()), return_exceptions=True)

    async def _refresh_loop(self) -> None:
        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(self._refresh_interval):
                    await self._stop.wait()
                    return
            await self.refresh_all()

    async def refresh_all(self) -> None:
        """Re-fetch every connected upstream's tools and tell whoever is listening."""
        results = await asyncio.gather(
            *(c.refresh_tools() for c in self.connections.values() if c.is_up),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, BaseException):
                logger.warning("tool refresh failed", extra={"warden": {"error": str(result)}})
        await self._notify_tools_changed()

    async def _notify_tools_changed(self) -> None:
        if self.on_tools_changed is None:
            return
        outcome = self.on_tools_changed(self.tools_by_upstream())
        if asyncio.iscoroutine(outcome):
            await outcome

    def get(self, name: str) -> UpstreamConnection | None:
        return self.connections.get(name)

    def tools_by_upstream(self) -> dict[str, tuple[Tool, ...]]:
        """Tools of every upstream that is currently up. Down upstreams are simply absent."""
        return {
            name: connection.tools
            for name, connection in self.connections.items()
            if connection.is_up
        }

    def health(self) -> Mapping[str, UpstreamHealth]:
        return {name: connection.health for name, connection in self.connections.items()}


__all__ = [
    "UpstreamConnection",
    "UpstreamHealth",
    "UpstreamManager",
    "UpstreamState",
    "UpstreamUnavailable",
]
