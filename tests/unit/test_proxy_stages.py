"""ResolveTool, ForwardToUpstream and the denial result shape."""

from __future__ import annotations

from typing import Any

import pytest
from mcp_types import CallToolResult, TextContent, Tool

from warden.config import Risk, ServersConfig, StdioTransport, UpstreamConfig
from warden.errors import ReasonCode
from warden.pipeline import Decision, RequestContext
from warden.proxy.registry import ToolRegistry
from warden.proxy.stages import ForwardToUpstream, ResolveTool, denial_result, result_size_bytes
from warden.upstream.manager import UpstreamUnavailable

pytestmark = pytest.mark.unit


def servers() -> ServersConfig:
    return ServersConfig(
        upstreams=[
            UpstreamConfig(
                name="files",
                transport=StdioTransport(command="true"),
                default_risk=Risk.READ,
                tools={"delete_file": {"risk": "destructive"}},
            )
        ]
    )


def registry_with(*names: str) -> ToolRegistry:
    registry = ToolRegistry()
    registry.replace(
        {
            "files": tuple(
                Tool(name=n, description="d", input_schema={"type": "object"}) for n in names
            )
        }
    )
    return registry


class FakeConnection:
    def __init__(self, *, up: bool = True, error: BaseException | None = None) -> None:
        self.is_up = up
        self._error = error
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.config = UpstreamConfig(
            name="files", transport=StdioTransport(command="true"), timeout_seconds=2.0
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, arguments))
        if self._error is not None:
            raise self._error
        return CallToolResult(content=[TextContent(type="text", text="ok")])


class FakeManager:
    def __init__(self, connections: dict[str, FakeConnection]) -> None:
        self._connections = connections

    def get(self, name: str) -> FakeConnection | None:
        return self._connections.get(name)


def ctx(tool_name: str | None = "files__read_file") -> RequestContext:
    return RequestContext(method="tools/call", tool_name=tool_name, arguments={"path": "a.md"})


async def test_resolve_maps_to_upstream_and_risk() -> None:
    stage = ResolveTool(registry_with("read_file", "delete_file"), servers())
    request = ctx()
    await stage.run(request)
    assert request.upstream == "files"
    assert request.upstream_tool == "read_file"
    assert request.risk is Risk.READ
    assert request.decision is Decision.ALLOW


async def test_resolve_applies_per_tool_risk_override() -> None:
    stage = ResolveTool(registry_with("delete_file"), servers())
    request = ctx("files__delete_file")
    await stage.run(request)
    assert request.risk is Risk.DESTRUCTIVE


async def test_resolve_denies_an_unknown_tool() -> None:
    stage = ResolveTool(registry_with("read_file"), servers())
    request = ctx("files__nope")
    await stage.run(request)
    assert request.reason_code is ReasonCode.UNKNOWN_TOOL
    assert request.decision is Decision.DENY


async def test_resolve_denies_a_missing_tool_name() -> None:
    stage = ResolveTool(registry_with("read_file"), servers())
    request = ctx(None)
    await stage.run(request)
    assert request.reason_code is ReasonCode.UNKNOWN_TOOL


async def test_forward_calls_the_upstream_with_the_upstream_name() -> None:
    connection = FakeConnection()
    stage = ForwardToUpstream(FakeManager({"files": connection}))  # type: ignore[arg-type]
    request = ctx()
    request.upstream, request.upstream_tool = "files", "read_file"
    await stage.run(request)
    assert connection.calls == [("read_file", {"path": "a.md"})]
    assert request.result is not None
    assert request.forwarded is True
    assert request.result_bytes == 2


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (TimeoutError(), ReasonCode.UPSTREAM_TIMEOUT),
        (UpstreamUnavailable("gone"), ReasonCode.UPSTREAM_UNAVAILABLE),
        (RuntimeError("boom"), ReasonCode.UPSTREAM_ERROR),
    ],
)
async def test_forward_maps_failures_to_reason_codes(
    error: BaseException, expected: ReasonCode
) -> None:
    connection = FakeConnection(error=error)
    stage = ForwardToUpstream(FakeManager({"files": connection}))  # type: ignore[arg-type]
    request = ctx()
    request.upstream, request.upstream_tool = "files", "read_file"
    await stage.run(request)
    assert request.reason_code is expected
    assert request.decision is Decision.DENY
    assert request.result is None


async def test_forward_denies_when_the_upstream_is_down() -> None:
    stage = ForwardToUpstream(FakeManager({"files": FakeConnection(up=False)}))  # type: ignore[arg-type]
    request = ctx()
    request.upstream, request.upstream_tool = "files", "read_file"
    await stage.run(request)
    assert request.reason_code is ReasonCode.UPSTREAM_UNAVAILABLE
    assert request.forwarded is False


async def test_forward_denies_when_the_upstream_is_unknown() -> None:
    stage = ForwardToUpstream(FakeManager({}))  # type: ignore[arg-type]
    request = ctx()
    request.upstream, request.upstream_tool = "nope", "read_file"
    await stage.run(request)
    assert request.reason_code is ReasonCode.UPSTREAM_UNAVAILABLE


async def test_forward_does_not_leak_the_upstream_exception_text() -> None:
    """An upstream error message could carry a path, a query or a credential."""
    secret = "postgres://user:hunter2@db/warden"
    connection = FakeConnection(error=RuntimeError(secret))
    stage = ForwardToUpstream(FakeManager({"files": connection}))  # type: ignore[arg-type]
    request = ctx()
    request.upstream, request.upstream_tool = "files", "read_file"
    await stage.run(request)
    rendered = denial_result(request)
    assert secret not in rendered.model_dump_json()


def test_denial_result_shape() -> None:
    request = ctx()
    request.deny(ReasonCode.DENIED_POLICY, "role reader may not call this tool", rule="r-1")
    result = denial_result(request)
    assert result.is_error is True
    assert result.structured_content == {
        "error": "WARDEN_DENIED:policy",
        "reason": "role reader may not call this tool",
        "request_id": request.request_id,
        "matched_rule": "r-1",
    }
    assert isinstance(result.content[0], TextContent)
    assert result.content[0].text.startswith("WARDEN_DENIED:policy")


def test_denial_result_includes_an_approval_id_when_pending() -> None:
    request = ctx()
    request.approval_id = "appr-1"
    request.pend(ReasonCode.PENDING_APPROVAL, "waiting for an admin")
    result = denial_result(request)
    assert result.structured_content is not None
    assert result.structured_content["approval_id"] == "appr-1"


def test_result_size_counts_text_and_structured_content() -> None:
    result = CallToolResult(
        content=[TextContent(type="text", text="abcd")], structured_content={"a": 1}
    )
    assert result_size_bytes(result) == len("abcd") + len('{"a": 1}')
