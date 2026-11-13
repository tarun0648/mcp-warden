"""The gateway's own MCP server: one endpoint in front of many upstreams.

Built on the SDK's low-level `Server` because the tool list is assembled at request time from
the registry and filtered per caller, which a decorator-registered tool set cannot express.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import mcp_types as types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel.server import Server

from warden.config import GatewayConfig, ServersConfig
from warden.logging import get_logger, principal_id_var, request_id_var
from warden.pipeline import Pipeline, Principal, RequestContext
from warden.proxy.registry import ToolRegistry
from warden.proxy.stages import denial_result
from warden.upstream.manager import UpstreamManager

logger = get_logger(__name__)

#: Resolves the authenticated caller for one request. Phase 3 has no auth, so the default
#: returns None and the pipeline treats every caller the same.
PrincipalResolver = Callable[[ServerRequestContext[Any]], Principal | None]

#: Decides which tools a caller may see. Phase 5 replaces the default with the policy engine.
ToolFilter = Callable[[Principal | None, list[types.Tool]], list[types.Tool]]


def _no_principal(_ctx: ServerRequestContext[Any]) -> Principal | None:
    return None


def _all_tools(_principal: Principal | None, tools: list[types.Tool]) -> list[types.Tool]:
    return tools


@dataclass(slots=True)
class GatewayDeps:
    """Everything the MCP layer needs. Assembled by `warden.main.create_app`."""

    settings_name: str
    gateway_config: GatewayConfig
    servers_config: ServersConfig
    registry: ToolRegistry
    upstreams: UpstreamManager
    #: Builds the pipeline for one request. A factory, not a single pipeline, because later
    #: phases need per-request state (the approval waiter, the audit writer).
    pipeline_factory: Callable[[], Pipeline]
    principal_resolver: PrincipalResolver = _no_principal
    tool_filter: ToolFilter = _all_tools


def build_mcp_server(deps: GatewayDeps) -> Server[Any]:
    """Create the MCP server that clients connect to."""

    async def on_list_tools(
        ctx: ServerRequestContext[Any], _params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        principal = deps.principal_resolver(ctx)
        _bind_log_context(principal)
        tools = deps.tool_filter(principal, deps.registry.definitions())
        logger.info(
            "tools/list",
            extra={
                "warden": {
                    "principal": principal.user_id if principal else None,
                    "tool_count": len(tools),
                }
            },
        )
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(
        ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        principal = deps.principal_resolver(ctx)
        request = RequestContext(
            method="tools/call",
            principal=principal,
            tool_name=params.name,
            arguments=dict(params.arguments or {}),
        )
        token = request_id_var.set(request.request_id)
        _bind_log_context(principal)
        try:
            await deps.pipeline_factory().run(request)
        finally:
            request_id_var.reset(token)
        if request.stopped or request.result is None:
            return denial_result(request)
        return request.result

    return Server(
        name="mcp-warden",
        version="0.1.0",
        title="mcp-warden",
        instructions=(
            "A security gateway in front of several MCP servers. Tool names are namespaced as "
            "<server>__<tool>. A refused call returns isError with a WARDEN_* reason code."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def _bind_log_context(principal: Principal | None) -> None:
    principal_id_var.set(principal.user_id if principal else None)


async def _noop(_: Any) -> None:  # pragma: no cover - placeholder for later phases
    return None


__all__ = ["GatewayDeps", "PrincipalResolver", "ToolFilter", "build_mcp_server"]
