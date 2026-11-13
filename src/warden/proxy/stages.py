"""The two stages the proxy needs before any security is added.

Later phases insert stages around these; the order in `warden.proxy.server` is the contract.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_types import CallToolResult, TextContent

from warden.config import ServersConfig
from warden.errors import ReasonCode
from warden.logging import get_logger
from warden.pipeline import RequestContext
from warden.proxy.registry import ToolRegistry
from warden.upstream.manager import UpstreamManager, UpstreamUnavailable

logger = get_logger(__name__)


def result_size_bytes(result: CallToolResult) -> int:
    """How many bytes of content a result carries, as the client will receive it."""
    total = 0
    for block in result.content:
        if isinstance(block, TextContent):
            total += len(block.text.encode("utf-8"))
        else:
            total += len(block.model_dump_json().encode("utf-8"))
    if result.structured_content is not None:
        total += len(json.dumps(result.structured_content, default=str).encode("utf-8"))
    return total


class ResolveTool:
    """Turn the client's namespaced tool name into an upstream and an upstream tool name."""

    name = "resolve"

    def __init__(self, registry: ToolRegistry, servers: ServersConfig) -> None:
        self._registry = registry
        self._servers = servers

    async def run(self, ctx: RequestContext) -> None:
        if ctx.tool_name is None:
            ctx.deny(ReasonCode.UNKNOWN_TOOL, "no tool name was given")
            return
        registered = self._registry.get(ctx.tool_name)
        if registered is None:
            ctx.deny(ReasonCode.UNKNOWN_TOOL, f"unknown tool '{ctx.tool_name}'")
            return
        ctx.upstream = registered.upstream
        ctx.upstream_tool = registered.upstream_tool
        upstream_config = self._servers.by_name(registered.upstream)
        if upstream_config is not None:
            ctx.risk = upstream_config.risk_for(registered.upstream_tool)


class ForwardToUpstream:
    """Call the upstream tool and store its result, mapping every failure to a reason code."""

    name = "forward"

    def __init__(self, upstreams: UpstreamManager) -> None:
        self._upstreams = upstreams

    async def run(self, ctx: RequestContext) -> None:
        if ctx.upstream is None or ctx.upstream_tool is None:  # pragma: no cover - resolve first
            ctx.deny(ReasonCode.UNKNOWN_TOOL, "the tool was not resolved")
            return
        connection = self._upstreams.get(ctx.upstream)
        if connection is None or not connection.is_up:
            ctx.deny(
                ReasonCode.UPSTREAM_UNAVAILABLE,
                f"upstream '{ctx.upstream}' is not available",
            )
            return
        try:
            ctx.forwarded = True
            result = await connection.call_tool(ctx.upstream_tool, ctx.arguments)
        except TimeoutError:
            ctx.deny(
                ReasonCode.UPSTREAM_TIMEOUT,
                f"upstream '{ctx.upstream}' did not answer within "
                f"{connection.config.timeout_seconds:g}s",
            )
            return
        except UpstreamUnavailable:
            ctx.deny(ReasonCode.UPSTREAM_UNAVAILABLE, f"upstream '{ctx.upstream}' is not available")
            return
        except Exception as exc:
            logger.warning(
                "upstream call failed",
                extra={
                    "warden": {
                        "upstream": ctx.upstream,
                        "tool": ctx.tool_name,
                        "error": f"{type(exc).__name__}: {exc}"[:300],
                    }
                },
            )
            ctx.deny(
                ReasonCode.UPSTREAM_ERROR,
                f"upstream '{ctx.upstream}' failed to run the tool",
            )
            return
        ctx.result = result
        ctx.result_bytes = result_size_bytes(result)


def denial_result(ctx: RequestContext) -> CallToolResult:
    """Render a stopped request as the structured error result the client receives.

    Hard rule 4: a denial is a tool result with `isError=true` and a machine-readable reason
    code, not a protocol error, because the caller is a model that has to understand it.
    """
    body: dict[str, Any] = {
        "error": str(ctx.reason_code),
        "reason": ctx.reason or "",
        "request_id": ctx.request_id,
    }
    if ctx.matched_rule:
        body["matched_rule"] = ctx.matched_rule
    if ctx.approval_id:
        body["approval_id"] = ctx.approval_id
    text = f"{ctx.reason_code}: {ctx.reason or ''}".strip()
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=body,
        is_error=True,
    )


__all__ = ["ForwardToUpstream", "ResolveTool", "denial_result", "result_size_bytes"]
