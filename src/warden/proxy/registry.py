"""The namespaced tool registry.

Clients see one flat tool list whose names are `<server>__<tool>`. The registry is the only
place that knows which upstream a gateway-visible name belongs to, and it refuses names that
would make that mapping ambiguous.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from mcp_types import Tool

from warden.config import NAMESPACE_SEP, TOOL_NAME_RE, namespaced
from warden.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    """One upstream tool as the gateway exposes it."""

    #: The gateway-visible name, `<server>__<tool>`.
    name: str
    upstream: str
    #: The upstream's own name for the tool, which is what we forward.
    upstream_tool: str
    definition: Tool

    def public_definition(self) -> Tool:
        """The definition to advertise: the upstream's, renamed to the namespaced name."""
        return self.definition.model_copy(update={"name": self.name})


def is_valid_upstream_tool_name(name: str) -> bool:
    """Reject names that cannot be namespaced unambiguously.

    A name containing the separator would make `split_namespaced` ambiguous, and a name with
    characters outside the MCP tool-name shape has no business reaching a client.
    """
    if not name or NAMESPACE_SEP in name:
        return False
    return bool(TOOL_NAME_RE.match(name))


class ToolRegistry:
    """An immutable-by-replacement map from namespaced name to upstream tool."""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}
        self._rejected: dict[str, str] = {}

    def replace(self, tools_by_upstream: Mapping[str, tuple[Tool, ...]]) -> None:
        """Rebuild the whole registry from the current upstream listings."""
        fresh: dict[str, RegisteredTool] = {}
        rejected: dict[str, str] = {}
        for upstream, tools in sorted(tools_by_upstream.items()):
            for tool in tools:
                if not is_valid_upstream_tool_name(tool.name):
                    rejected[f"{upstream}:{tool.name}"] = "tool name is not a valid identifier"
                    logger.warning(
                        "rejected upstream tool name",
                        extra={"warden": {"upstream": upstream, "tool": tool.name}},
                    )
                    continue
                public = namespaced(upstream, tool.name)
                if public in fresh:  # pragma: no cover - server names are unique by config
                    rejected[f"{upstream}:{tool.name}"] = "duplicate namespaced name"
                    continue
                fresh[public] = RegisteredTool(
                    name=public, upstream=upstream, upstream_tool=tool.name, definition=tool
                )
        self._tools = fresh
        self._rejected = rejected

    def get(self, name: str) -> RegisteredTool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def definitions(self) -> list[Tool]:
        """Every registered tool, renamed for the client, in a stable order."""
        return [self._tools[name].public_definition() for name in sorted(self._tools)]

    def for_upstream(self, upstream: str) -> list[RegisteredTool]:
        return [tool for tool in self._tools.values() if tool.upstream == upstream]

    @property
    def rejected(self) -> Mapping[str, str]:
        """Upstream tools that were refused, and why. Surfaced by `warden tools`."""
        return dict(self._rejected)

    def __len__(self) -> int:
        return len(self._tools)

    def __iter__(self) -> Iterator[RegisteredTool]:
        return iter(self._tools[name] for name in sorted(self._tools))

    def __contains__(self, name: object) -> bool:
        return name in self._tools


__all__ = ["RegisteredTool", "ToolRegistry", "is_valid_upstream_tool_name"]
