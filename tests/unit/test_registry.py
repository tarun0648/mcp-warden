"""The namespaced tool registry."""

from __future__ import annotations

import pytest
from mcp_types import Tool

from warden.proxy.registry import ToolRegistry, is_valid_upstream_tool_name

pytestmark = pytest.mark.unit


def tool(name: str, description: str = "d") -> Tool:
    return Tool(name=name, description=description, input_schema={"type": "object"})


def test_namespacing_and_lookup() -> None:
    registry = ToolRegistry()
    registry.replace({"files": (tool("read_file"), tool("write_file")), "notes": (tool("get"),)})
    assert registry.names() == ["files__read_file", "files__write_file", "notes__get"]
    found = registry.get("files__read_file")
    assert found is not None
    assert (found.upstream, found.upstream_tool) == ("files", "read_file")
    assert registry.get("files__missing") is None
    assert registry.get("read_file") is None
    assert len(registry) == 3
    assert "notes__get" in registry


def test_definitions_are_renamed_but_otherwise_untouched() -> None:
    registry = ToolRegistry()
    original = Tool(
        name="read_file",
        description="Read a file.",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    )
    registry.replace({"files": (original,)})
    published = registry.definitions()[0]
    assert published.name == "files__read_file"
    assert published.description == "Read a file."
    assert published.input_schema == original.input_schema


@pytest.mark.parametrize("name", ["read_file", "get.note", "a", "tool-name", "_x"])
def test_valid_upstream_tool_names(name: str) -> None:
    assert is_valid_upstream_tool_name(name)


@pytest.mark.parametrize(
    "name",
    ["", "has space", "has__separator", "1leading_digit", "a" * 70, "semi;colon", "slash/name"],
)
def test_invalid_upstream_tool_names(name: str) -> None:
    assert not is_valid_upstream_tool_name(name)


def test_invalid_names_are_rejected_and_reported() -> None:
    """A tool whose name embeds the separator would make the mapping ambiguous."""
    registry = ToolRegistry()
    registry.replace({"files": (tool("read_file"), tool("evil__shadow"), tool("bad name"))})
    assert registry.names() == ["files__read_file"]
    assert set(registry.rejected) == {"files:evil__shadow", "files:bad name"}


def test_replace_drops_tools_that_are_gone() -> None:
    registry = ToolRegistry()
    registry.replace({"files": (tool("read_file"),), "notes": (tool("get"),)})
    registry.replace({"notes": (tool("get"),)})
    assert registry.names() == ["notes__get"]
    assert registry.get("files__read_file") is None


def test_for_upstream_filters() -> None:
    registry = ToolRegistry()
    registry.replace({"files": (tool("a"), tool("b")), "notes": (tool("c"),)})
    assert {t.upstream_tool for t in registry.for_upstream("files")} == {"a", "b"}
    assert registry.for_upstream("nope") == []


def test_iteration_is_sorted() -> None:
    registry = ToolRegistry()
    registry.replace({"z": (tool("a"),), "a": (tool("z"),)})
    assert [t.name for t in registry] == ["a__z", "z__a"]
