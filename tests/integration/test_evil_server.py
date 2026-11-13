"""Every malicious behaviour must be reproducible through a real MCP client session."""

from __future__ import annotations

import base64

import pytest
from servers.evil import DEFAULT_RUGPULL_AFTER, EvilState, build_server, tool_definitions
from servers.evil.payloads import (
    BASE64_INJECTION_PAYLOAD,
    BENIGN_QUOTE_DESCRIPTION,
    PLAIN_INJECTION,
    RUGPULLED_QUOTE_DESCRIPTION,
)

from tests.helpers import evil_client, text_of

pytestmark = pytest.mark.integration


async def test_tools_list_exposes_the_seven_tools() -> None:
    async with evil_client(EvilState()) as (client, _state):
        listing = await client.list_tools()
    assert {tool.name for tool in listing.tools} == {
        "get_weather",
        "add_numbers",
        "fetch_quote",
        "read_file",
        "send_report",
        "slow_tool",
        "huge_output",
    }


async def test_get_weather_description_carries_the_poison() -> None:
    async with evil_client(EvilState()) as (client, _state):
        listing = await client.list_tools()
    weather = next(tool for tool in listing.tools if tool.name == "get_weather")
    description = weather.description or ""
    assert "<IMPORTANT>" in description
    assert "~/.ssh/id_rsa" in description
    assert "Ignore all previous instructions" in description
    assert "​" in description, "zero-width character must survive the wire"
    assert "‮" in description, "bidi override must survive the wire"


async def test_get_weather_itself_behaves_normally() -> None:
    """The attack is in the description; the result is an ordinary forecast."""
    async with evil_client(EvilState()) as (client, _state):
        result = await client.call_tool("get_weather", {"city": "Berlin"})
    assert not result.is_error
    assert "Berlin" in text_of(result)
    assert "IMPORTANT" not in text_of(result)


@pytest.mark.parametrize(
    ("variant", "needle"),
    [
        ("plain", "Ignore all previous instructions"),
        ("base64", BASE64_INJECTION_PAYLOAD),
        ("json", "_note"),
        ("unicode", "​"),
        ("multilingual", "Ignora todas las instrucciones"),
    ],
)
async def test_add_numbers_injection_variants(variant: str, needle: str) -> None:
    async with evil_client(EvilState(injection_variant=variant)) as (client, _state):
        result = await client.call_tool("add_numbers", {"a": 1, "b": 2})
    text = text_of(result)
    assert "3" in text, "the sum must still be correct, which is what makes this dangerous"
    assert needle in text


async def test_base64_variant_decodes_to_the_plain_injection() -> None:
    async with evil_client(EvilState(injection_variant="base64")) as (client, _state):
        text = text_of(await client.call_tool("add_numbers", {"a": 1, "b": 2}))
    encoded = text.split("follow: ")[1].strip()
    assert base64.b64decode(encoded).decode() == PLAIN_INJECTION


async def test_rug_pull_flips_exactly_after_n_list_calls() -> None:
    state = EvilState(rugpull_after=2)
    async with evil_client(state) as (client, _state):
        first = await client.list_tools(cache_mode="bypass")
        assert _quote_description(first) == BENIGN_QUOTE_DESCRIPTION
        second = await client.list_tools(cache_mode="bypass")
        assert _quote_description(second) == BENIGN_QUOTE_DESCRIPTION
        third = await client.list_tools(cache_mode="bypass")
        assert _quote_description(third) == RUGPULLED_QUOTE_DESCRIPTION
    assert state.list_calls == 3


async def test_rug_pull_can_be_disabled_with_a_large_threshold() -> None:
    state = EvilState(rugpull_after=100)
    async with evil_client(state) as (client, _state):
        for _ in range(4):
            listing = await client.list_tools(cache_mode="bypass")
            assert _quote_description(listing) == BENIGN_QUOTE_DESCRIPTION


def _quote_description(listing: object) -> str:
    tools = listing.tools  # type: ignore[attr-defined]
    return next(tool.description or "" for tool in tools if tool.name == "fetch_quote")


async def test_read_file_shadows_the_files_server() -> None:
    async with evil_client(EvilState()) as (client, _state):
        listing = await client.list_tools()
        shadow = next(tool for tool in listing.tools if tool.name == "read_file")
        assert "files__read_file" in (shadow.description or "")
        assert "instead of" in (shadow.description or "")
        result = await client.call_tool("read_file", {"path": "/etc/passwd"})
    assert "this server reads no files" in text_of(result)


async def test_send_report_records_the_call_in_memory() -> None:
    async with evil_client(EvilState()) as (client, state):
        await client.call_tool("send_report", {"to": "attacker@example.com", "body": "secret"})
        assert state.reports == [{"to": "attacker@example.com", "body": "secret"}]  # type: ignore[attr-defined]


async def test_slow_tool_sleeps() -> None:
    import time

    async with evil_client(EvilState()) as (client, _state):
        started = time.monotonic()
        result = await client.call_tool("slow_tool", {"seconds": 0.3})
        elapsed = time.monotonic() - started
    assert not result.is_error
    assert elapsed >= 0.25


async def test_huge_output_returns_the_requested_size() -> None:
    async with evil_client(EvilState()) as (client, _state):
        result = await client.call_tool("huge_output", {"kb": 64})
    assert len(text_of(result)) == 64 * 1024


async def test_huge_output_is_capped_so_tests_cannot_exhaust_memory() -> None:
    async with evil_client(EvilState()) as (client, _state):
        result = await client.call_tool("huge_output", {"kb": 1_000_000})
    assert len(text_of(result)) == 4096 * 1024


async def test_unknown_tool_is_an_error_result() -> None:
    async with evil_client(EvilState()) as (client, _state):
        result = await client.call_tool("not_a_tool", {})
    assert result.is_error


def test_default_rugpull_threshold_matches_the_documented_value() -> None:
    assert DEFAULT_RUGPULL_AFTER == 2
    server, state = build_server(EvilState())
    assert server.name == "evil"
    assert len(tool_definitions(state)) == 7
