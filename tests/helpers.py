"""Helpers for driving MCP servers from tests.

The SDK's client is an anyio context manager: entering it in a pytest async fixture and leaving
it in the fixture's finaliser crosses tasks, which anyio refuses. So tests enter the client
inside their own body with `async with notes_client(...)`, which keeps setup and teardown in one
task and keeps the lifetime visible in the test.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from mcp import Client
from mcp_types import CallToolResult, TextContent

REPO_ROOT = Path(__file__).resolve().parents[1]


@asynccontextmanager
async def notes_client(tmp_path: Path) -> AsyncIterator[Client]:
    """A client connected in-process to a notes_db server with a temporary database."""
    from servers.notes_db import build_server
    from servers.notes_db.store import NoteStore

    store = NoteStore(tmp_path / "notes.sqlite3")
    async with Client(build_server(store)) as session:
        yield session


@asynccontextmanager
async def evil_client(state: object | None = None) -> AsyncIterator[tuple[Client, object]]:
    """A client connected in-process to the evil server, with its state object for assertions."""
    from servers.evil import EvilState, build_server

    server, current = build_server(state if isinstance(state, EvilState) else None)
    async with Client(server) as session:
        yield session, current


@asynccontextmanager
async def files_client(root: Path) -> AsyncIterator[Client]:
    """A client connected in-process to a files server sandboxed at `root`."""
    from servers.files import build_server

    async with Client(build_server(root)) as session:
        yield session


def payload(result: CallToolResult) -> dict[str, Any]:
    """The tool's structured result, falling back to parsing its text content as JSON."""
    assert not result.is_error, f"unexpected error result: {text_of(result)}"
    if result.structured_content is not None:
        return dict(result.structured_content)
    return dict(json.loads(text_of(result)))


def text_of(result: CallToolResult) -> str:
    """The first text block of a result."""
    assert result.content, "result has no content"
    block = result.content[0]
    assert isinstance(block, TextContent), f"expected text content, got {type(block).__name__}"
    return block.text


def error_text(result: CallToolResult) -> str:
    """The message of an is_error result, asserting that it is one and carries no traceback."""
    assert result.is_error, f"expected an error result, got: {result.content}"
    message = text_of(result)
    assert "Traceback" not in message, "an error message must never contain a stack trace"
    return message


# ----------------------------------------------------------------------------------------------
# Running the gateway itself
# ----------------------------------------------------------------------------------------------


def free_port() -> int:
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def stdio_upstream(name: str, module: str, env: dict[str, str], **kwargs: Any) -> Any:
    """An UpstreamConfig that runs one of our servers as a child process, as production does."""
    from warden.config import StdioTransport, UpstreamConfig

    return UpstreamConfig(
        name=name,
        transport=StdioTransport(
            command=sys.executable,
            args=["-m", module],
            env={"PYTHONPATH": str(REPO_ROOT), **env},
            cwd=str(REPO_ROOT),
        ),
        **kwargs,
    )


def test_servers_config(tmp_path: Path, *, include_evil: bool = False, **overrides: Any) -> Any:
    """A servers config whose upstreams write only inside `tmp_path`."""
    from warden.config import Risk, ServersConfig

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(exist_ok=True)
    upstreams = [
        stdio_upstream(
            "notes_db",
            "servers.notes_db",
            {"NOTES_DB_PATH": str(tmp_path / "notes.sqlite3")},
            trusted=True,
            timeout_seconds=20.0,
            default_risk=Risk.READ,
            tools={"create_note": {"risk": "write"}, "delete_note": {"risk": "destructive"}},
        ),
        stdio_upstream(
            "files",
            "servers.files",
            {"FILES_SANDBOX_ROOT": str(sandbox)},
            trusted=True,
            timeout_seconds=20.0,
            default_risk=Risk.READ,
            tools={"write_file": {"risk": "write"}, "delete_file": {"risk": "destructive"}},
        ),
    ]
    if include_evil:
        upstreams.append(
            stdio_upstream(
                "evil",
                "servers.evil",
                {"EVIL_RUGPULL_AFTER": "2", **overrides.pop("evil_env", {})},
                trusted=False,
                timeout_seconds=overrides.pop("evil_timeout", 2.0),
                default_risk=Risk.WRITE,
                tools={"send_report": {"risk": "destructive"}},
            )
        )
    return ServersConfig(upstreams=upstreams)


def test_settings(tmp_path: Path, **overrides: Any) -> Any:
    """Settings for a gateway under test: temp database, temp keys, real config dir."""
    from warden.config import Settings

    defaults: dict[str, Any] = {
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'warden.sqlite3'}",
        "redis_url": "redis://localhost:6379/15",
        "config_dir": REPO_ROOT / "config",
        "jwt_key_dir": tmp_path / "keys",
        "log_level": "WARNING",
        "otel_enabled": False,
        "classifier_enabled": False,
    }
    defaults.update(overrides)
    return Settings(**defaults)


@dataclass
class RunningGateway:
    """A gateway served by uvicorn on a real port, with its app state reachable."""

    url: str
    app: Any
    #: Credentials minted for the test, by role name.
    keys: dict[str, str] = field(default_factory=dict)
    database_url: str = ""

    def auth(self, role: str = "admin") -> dict[str, str]:
        """An Authorization header for the credential minted for `role`."""
        return {"Authorization": f"Bearer {self.keys[role]}"}

    @property
    def mcp_url(self) -> str:
        return f"{self.url}/mcp"

    @property
    def registry(self) -> Any:
        return self.app.state.registry

    @property
    def upstreams(self) -> Any:
        return self.app.state.upstreams

    async def on_server_loop(self, coro: Any, *, timeout: float = 30.0) -> Any:
        """Run a coroutine on the gateway's own event loop and wait for it.

        The upstream connections are owned by tasks in the server thread's loop, so a test
        must not await them directly; doing so raises "attached to a different loop".
        """
        future = asyncio.run_coroutine_threadsafe(coro, self.app.state.loop)
        return await asyncio.to_thread(future.result, timeout)


@contextmanager
def serve_app(
    app: Any, *, port: int | None = None, startup_timeout: float = 60.0
) -> Iterator[RunningGateway]:
    """Run a Starlette app under uvicorn in a background thread.

    Real HTTP, real Streamable HTTP transport, real lifespan: the upstream manager's tasks live
    in the server's own event loop, exactly as in production.
    """
    chosen = port or free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=chosen, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="gateway-under-test", daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{chosen}"
    try:
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if getattr(server, "started", False):
                break
            if not thread.is_alive():
                raise AssertionError("the gateway thread exited during startup")
            time.sleep(0.05)
        else:
            raise AssertionError("the gateway did not start in time")
        yield RunningGateway(url=base, app=app)
    finally:
        server.should_exit = True
        thread.join(timeout=30)


#: Roles the test gateway mints an API key for, so a test can call as any of them.
TEST_ROLES = ("admin", "reader", "editor", "redteam")


def run_async(factory: Any) -> Any:
    """Run `factory()` on a fresh event loop in a worker thread.

    Needed because an async test already owns the loop in its own thread, and a SQLAlchemy
    async engine binds its connections to whichever loop creates them. Setup work therefore
    gets its own loop *and* its own engine, disposed before the gateway starts.
    """
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["value"] = asyncio.run(factory())
        except BaseException as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=target, name="test-async-setup")
    thread.start()
    thread.join(120)
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def prepare_gateway_state(settings: Any) -> dict[str, str]:
    """Create the schema, the signing key, and one API key per test role.

    Returns the raw secrets by role. The engine used here is thrown away: the gateway builds
    its own inside the server thread's loop, where every connection it makes will live.
    """
    from warden.auth.api_keys import ApiKeyStore
    from warden.auth.jwt_keys import JwtKeyStore
    from warden.db.engine import Database

    JwtKeyStore(settings.jwt_key_dir).initialise()

    async def setup() -> dict[str, str]:
        database = Database(settings.database_url)
        try:
            await database.create_all()
            store = ApiKeyStore(database)
            minted: dict[str, str] = {}
            for role in TEST_ROLES:
                generated = await store.create(f"{role}-user", [role], label=f"test {role}")
                minted[role] = generated.secret
            return minted
        finally:
            await database.dispose()

    return run_async(setup)


@contextmanager
def running_gateway(
    tmp_path: Path,
    *,
    include_evil: bool = False,
    settings_overrides: dict[str, Any] | None = None,
    gateway_overrides: dict[str, Any] | None = None,
    servers_config: Any | None = None,
    wait_upstreams: float = 40.0,
    **servers_kwargs: Any,
) -> Iterator[RunningGateway]:
    """A fully wired gateway in front of real upstream subprocesses, with credentials minted."""
    from warden.auth.tokens import NullRevocationStore
    from warden.config import GatewayConfig
    from warden.health import Readiness
    from warden.main import create_app

    settings = test_settings(tmp_path, **(settings_overrides or {}))
    servers = (
        servers_config
        if servers_config is not None
        else test_servers_config(tmp_path, include_evil=include_evil, **servers_kwargs)
    )
    keys = prepare_gateway_state(settings)
    gateway_config = GatewayConfig(**(gateway_overrides or {}))
    app = create_app(
        settings,
        readiness=Readiness({}),
        gateway_config=gateway_config,
        servers_config=servers,
        # Integration tests must not need a Redis daemon; revocation has its own unit tests
        # against fakeredis and its own Redis-marked integration test.
        revocations=NullRevocationStore(),
        upstream_wait_seconds=wait_upstreams,
    )
    with serve_app(app) as handle:
        handle.keys.update(keys)
        handle.database_url = settings.database_url
        wait_for_tools(handle, timeout=wait_upstreams + 20)
        yield handle


@contextmanager
def header_recording_upstream(
    port: int | None = None,
) -> Iterator[tuple[str, list[dict[str, str]]]]:
    """An MCP server over HTTP that records the headers of every request it receives.

    Used to prove the gateway never forwards a client's Authorization header to an upstream.
    """
    import mcp_types as types
    from mcp.server.lowlevel.server import Server
    from mcp.server.streamable_http_manager import (
        StreamableHTTPASGIApp,
        StreamableHTTPSessionManager,
    )
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.applications import Starlette
    from starlette.routing import Route

    seen: list[dict[str, str]] = []

    async def on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="echo",
                    description="Return the text it was given.",
                    input_schema={
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"],
                    },
                )
            ]
        )

    async def on_call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        text = str((params.arguments or {}).get("text", ""))
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    server: Server[Any] = Server(
        name="recorder",
        version="0.1.0",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    manager = StreamableHTTPSessionManager(
        app=server,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    class Recorder:
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] == "http":
                seen.append(
                    {
                        bytes(k).decode("latin-1").lower(): bytes(v).decode("latin-1")
                        for k, v in scope.get("headers", [])
                    }
                )
            await self.inner(scope, receive, send)

    import contextlib as _contextlib

    @_contextlib.asynccontextmanager
    async def lifespan(_: Any) -> AsyncIterator[None]:
        async with manager.run():
            yield

    app = Starlette(
        routes=[Route("/mcp", endpoint=Recorder(StreamableHTTPASGIApp(manager)))],
        lifespan=lifespan,
    )
    chosen = port or free_port()
    with serve_app(app, port=chosen):
        yield f"http://127.0.0.1:{chosen}/mcp", seen


def wait_for_tools(handle: RunningGateway, *, timeout: float = 60.0, minimum: int = 1) -> None:
    """Block until the gateway's registry has tools, so tests do not race startup."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if len(handle.registry) >= minimum:
            return
        time.sleep(0.1)
    raise AssertionError(
        f"gateway registry still has {len(handle.registry)} tools after {timeout:g}s; "
        f"health={ {k: v.as_dict() for k, v in handle.upstreams.health().items()} }"
    )


async def wait_until(predicate: Any, *, timeout: float = 20.0, interval: float = 0.1) -> None:
    """Poll `predicate` until it is true or the timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(interval)
    raise AssertionError("condition was not met in time")


def http_get(url: str, **kwargs: Any) -> httpx.Response:
    return httpx.get(url, timeout=10.0, **kwargs)


@asynccontextmanager
async def gateway_client(
    handle: RunningGateway, headers: dict[str, str] | None = None
) -> AsyncIterator[Client]:
    """An MCP client talking to the running gateway over Streamable HTTP."""
    import httpx2

    if headers:
        async with httpx2.AsyncClient(headers=headers, timeout=30.0) as http_client:
            from mcp.client.streamable_http import streamable_http_client

            async with Client(
                streamable_http_client(handle.mcp_url, http_client=http_client)
            ) as session:
                yield session
    else:
        async with Client(handle.mcp_url) as session:
            yield session
