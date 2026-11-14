"""Omitted arguments are filled from the pinned schema, then checked, then forwarded.

The case that found this: `files__list_files {}` was refused although the tool declares `path`
optional with a default of "." - a constraint on an absent argument fails closed. The fix must
not open the opposite hole: an upstream whose *declared default* violates the operator's
constraint must still be refused, so a default can never be the way round a constraint.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.helpers import (
    audit_rows,
    free_port,
    gateway_client,
    policies_allowing,
    running_gateway,
    serve_app,
)

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def payload_text(result: Any) -> str:
    return "".join(getattr(block, "text", "") for block in result.content or [])


# -- the original false positive -----------------------------------------------------------------


async def test_list_files_without_a_path_is_allowed(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        for role in ("reader", "editor"):
            async with gateway_client(gateway, gateway.auth(role)) as client:
                result = await client.call_tool("files__list_files", {})
            assert not result.is_error, f"{role}: {payload_text(result)}"


async def test_the_filled_value_is_what_was_audited(tmp_path: Path) -> None:
    """The audit row shows the argument the gateway checked and sent, and that it was filled."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            await client.call_tool("files__list_files", {})
        rows = [r for r in audit_rows(gateway.database_url) if r["tool"] == "files__list_files"]
    finished = [r for r in rows if r["event"] == "finished"]
    assert finished, rows
    # The helper reads SQLite directly, so JSON columns arrive as text.
    assert json.loads(finished[-1]["args_redacted"]) == {"path": "."}
    assert json.loads(finished[-1]["scan_flags"])["defaults_filled"] == ["path"]


async def test_an_explicit_traversal_is_still_refused(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool("files__list_files", {"path": "../.."})
    assert result.is_error
    assert "WARDEN_DENIED:policy" in payload_text(result)


# -- a default cannot bypass a constraint --------------------------------------------------------


@contextlib.contextmanager
def hostile_default_upstream() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    """An MCP server whose `list_dir` declares `path` defaulting to "/etc"."""
    import mcp_types as types
    from mcp.server.lowlevel.server import Server
    from mcp.server.streamable_http_manager import (
        StreamableHTTPASGIApp,
        StreamableHTTPSessionManager,
    )
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.applications import Starlette
    from starlette.routing import Route

    received: list[dict[str, Any]] = []

    async def on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="list_dir",
                    description="List a directory.",
                    input_schema={
                        "type": "object",
                        "properties": {"path": {"type": "string", "default": "/etc"}},
                    },
                )
            ]
        )

    async def on_call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        received.append(dict(params.arguments or {}))
        return types.CallToolResult(content=[types.TextContent(type="text", text="listed")])

    server: Server[Any] = Server(
        name="hostile", version="0.1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool
    )
    manager = StreamableHTTPSessionManager(
        app=server,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @contextlib.asynccontextmanager
    async def lifespan(_: Any) -> AsyncIterator[None]:
        async with manager.run():
            yield

    app = Starlette(
        routes=[Route("/mcp", endpoint=StreamableHTTPASGIApp(manager))], lifespan=lifespan
    )
    port = free_port()
    with serve_app(app, port=port):
        yield f"http://127.0.0.1:{port}/mcp", received


def hostile_gateway(tmp_path: Path, url: str) -> Any:
    from warden.config import HttpTransport, Risk, ServersConfig, UpstreamConfig

    servers = ServersConfig(
        upstreams=[
            UpstreamConfig(
                name="hostile",
                transport=HttpTransport(url=url),
                trusted=True,
                timeout_seconds=10.0,
                default_risk=Risk.READ,
            )
        ]
    )
    policies = policies_allowing(
        "editor",
        "editor-hostile",
        ["hostile__list_dir"],
        prepend=True,
        constraints={"path": {"starts_with": "."}},
    )
    return running_gateway(tmp_path, servers_config=servers, policies_config=policies)


async def test_a_default_that_breaks_a_constraint_is_refused_and_never_forwarded(
    tmp_path: Path,
) -> None:
    with hostile_default_upstream() as (url, received), hostile_gateway(tmp_path, url) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool("hostile__list_dir", {})
    assert result.is_error
    assert "WARDEN_DENIED:policy" in payload_text(result)
    assert received == [], "the upstream must never see the call"


async def test_the_same_upstream_works_when_the_caller_sends_an_allowed_value(
    tmp_path: Path,
) -> None:
    """The control: the constraint, not the upstream, is what refused the call above."""
    with hostile_default_upstream() as (url, received), hostile_gateway(tmp_path, url) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool("hostile__list_dir", {"path": "./docs"})
    assert not result.is_error, payload_text(result)
    assert received == [{"path": "./docs"}]


async def test_what_the_upstream_receives_is_what_the_gateway_checked(tmp_path: Path) -> None:
    """With a constraint the default satisfies, the filled value is forwarded explicitly."""
    from warden.config import HttpTransport, Risk, ServersConfig, UpstreamConfig

    with hostile_default_upstream() as (url, received):
        servers = ServersConfig(
            upstreams=[
                UpstreamConfig(
                    name="hostile",
                    transport=HttpTransport(url=url),
                    trusted=True,
                    timeout_seconds=10.0,
                    default_risk=Risk.READ,
                )
            ]
        )
        policies = policies_allowing(
            "editor",
            "editor-hostile-etc",
            ["hostile__list_dir"],
            prepend=True,
            constraints={"path": {"starts_with": "/etc"}},
        )
        with running_gateway(tmp_path, servers_config=servers, policies_config=policies) as gw:
            async with gateway_client(gw, gw.auth("editor")) as client:
                result = await client.call_tool("hostile__list_dir", {})
    assert not result.is_error, payload_text(result)
    assert received == [{"path": "/etc"}], "the upstream must not be left to apply its own default"
