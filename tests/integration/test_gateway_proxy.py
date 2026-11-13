"""A real MCP client, through the gateway over Streamable HTTP, to real upstream subprocesses."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import (
    approve_tool,
    error_text,
    gateway_client,
    payload,
    running_gateway,
    wait_until,
)

pytestmark = pytest.mark.integration


async def test_tools_list_is_namespaced_and_aggregated(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            listing = await client.list_tools()
    names = {tool.name for tool in listing.tools}
    assert "notes_db__list_notes" in names
    assert "files__read_file" in names
    assert all("__" in name for name in names)
    assert len([n for n in names if n.startswith("notes_db__")]) == 6
    assert len([n for n in names if n.startswith("files__")]) == 4


async def test_descriptions_survive_the_proxy(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            listing = await client.list_tools()
    tool = next(t for t in listing.tools if t.name == "notes_db__list_notes")
    assert tool.description == "List notes, oldest first."
    assert tool.input_schema["properties"]["limit"]["maximum"] == 200


async def test_write_then_read_round_trips_through_the_gateway(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            written = payload(
                await client.call_tool(
                    "files__write_file", {"path": "notes/a.md", "content": "hello gateway"}
                )
            )
            assert written["path"] == "notes/a.md"
            read = payload(await client.call_tool("files__read_file", {"path": "notes/a.md"}))
    assert read["content"] == "hello gateway"
    assert (tmp_path / "sandbox" / "notes" / "a.md").read_text() == "hello gateway"


async def test_notes_tools_work_through_the_gateway(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            listed = payload(await client.call_tool("notes_db__list_notes", {"limit": 3}))
    assert len(listed["notes"]) == 3


async def test_unknown_tool_is_denied_with_a_reason_code(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            result = await client.call_tool("files__nope", {})
            other = await client.call_tool("not_namespaced", {})
    assert "WARDEN_UNKNOWN_TOOL" in error_text(result)
    assert result.structured_content is not None
    assert result.structured_content["error"] == "WARDEN_UNKNOWN_TOOL"
    assert "request_id" in result.structured_content
    assert "WARDEN_UNKNOWN_TOOL" in error_text(other)


async def test_upstream_error_is_mapped_not_leaked(tmp_path: Path) -> None:
    """An upstream tool's own error comes back as the upstream's is_error result, intact."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            result = await client.call_tool("files__read_file", {"path": "missing.txt"})
    assert result.is_error
    assert "no such file" in error_text(result)


async def test_killing_one_upstream_removes_only_its_tools(tmp_path: Path) -> None:
    """One upstream failing must never take the others with it."""
    with running_gateway(
        tmp_path,
        gateway_overrides={
            "upstream_health_interval_seconds": 0.5,
            "tools_refresh_seconds": 1.0,
        },
    ) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            before = {tool.name for tool in (await client.list_tools()).tools}
            assert any(name.startswith("files__") for name in before)

            connection = gateway.upstreams.get("files")
            await gateway.on_server_loop(connection.stop())
            # No manual registry poke: the gateway's own refresh loop must notice.
            await wait_until(
                lambda: not any(name.startswith("files__") for name in gateway.registry.names()),
                timeout=30,
            )

            after = {tool.name for tool in (await client.list_tools(cache_mode="bypass")).tools}
            assert not any(name.startswith("files__") for name in after)
            assert any(name.startswith("notes_db__") for name in after)

            denied = await client.call_tool("files__read_file", {"path": "a.md"})
            assert "WARDEN_UNKNOWN_TOOL" in error_text(denied)

            still_works = payload(await client.call_tool("notes_db__list_notes", {"limit": 1}))
            assert len(still_works["notes"]) == 1


async def test_slow_upstream_hits_the_timeout(tmp_path: Path) -> None:
    with running_gateway(tmp_path, include_evil=True, evil_timeout=1.0) as gateway:
        # The evil server is untrusted, so its tools start quarantined; this test is about the
        # timeout, so an admin approves the one tool it needs.
        approve_tool(gateway, "evil__slow_tool")
        async with gateway_client(gateway, gateway.auth("redteam")) as client:
            result = await client.call_tool("evil__slow_tool", {"seconds": 10})
    assert "WARDEN_UPSTREAM_TIMEOUT" in error_text(result)
    assert result.structured_content is not None
    assert result.structured_content["error"] == "WARDEN_UPSTREAM_TIMEOUT"


async def test_twenty_concurrent_calls_all_succeed(tmp_path: Path) -> None:
    import asyncio

    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            results = await asyncio.gather(
                *(
                    client.call_tool("notes_db__get_note", {"note_id": (index % 10) + 1})
                    for index in range(20)
                )
            )
    assert len(results) == 20
    assert all(not result.is_error for result in results), [
        r.content for r in results if r.is_error
    ]


async def test_health_endpoints_served_alongside_mcp(tmp_path: Path) -> None:
    from tests.helpers import http_get

    with running_gateway(tmp_path) as gateway:
        assert http_get(f"{gateway.url}/healthz").status_code == 200
        assert http_get(f"{gateway.url}/readyz").status_code == 200
