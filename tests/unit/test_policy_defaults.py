"""Filling omitted arguments from the pinned schema."""

from __future__ import annotations

from typing import Any

import pytest
from mcp_types import Tool

from warden.pipeline import Decision, RequestContext
from warden.policy.defaults import FLAG, ApplySchemaDefaults, fill_defaults
from warden.proxy.registry import ToolRegistry
from warden.scan.definitions import definition_hash

pytestmark = pytest.mark.unit

SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "default": "."},
        "limit": {"type": "integer", "default": 20},
        "cursor": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None},
        "query": {"type": "string"},
    },
}


# -- fill_defaults -----------------------------------------------------------------------------


def test_an_omitted_argument_gets_its_declared_default() -> None:
    filled = fill_defaults(SCHEMA, {"query": "x"})
    assert filled.arguments == {"query": "x", "path": ".", "limit": 20}
    assert filled.names == ("limit", "path")


def test_a_value_the_caller_sent_is_never_replaced() -> None:
    filled = fill_defaults(SCHEMA, {"path": "notes", "limit": 5})
    assert filled.arguments["path"] == "notes"
    assert filled.arguments["limit"] == 5
    assert "path" not in filled.names


def test_an_explicit_null_from_the_caller_is_kept() -> None:
    """The caller chose null; the gateway checks that, not a substitute."""
    filled = fill_defaults(SCHEMA, {"path": None})
    assert filled.arguments["path"] is None
    assert "path" not in filled.names


def test_a_null_default_is_not_filled() -> None:
    """Filling `None` would make an `optional: true` constraint see a wrong-typed value."""
    filled = fill_defaults(SCHEMA, {})
    assert "cursor" not in filled.arguments


def test_a_property_with_no_default_stays_absent() -> None:
    assert "query" not in fill_defaults(SCHEMA, {}).arguments


def test_the_callers_mapping_is_not_mutated() -> None:
    original: dict[str, Any] = {"query": "x"}
    fill_defaults(SCHEMA, original)
    assert original == {"query": "x"}


def test_a_mutable_default_is_copied_not_shared() -> None:
    """Otherwise one request could change the default every later request receives."""
    schema = {"properties": {"tags": {"type": "array", "default": ["a"]}}}
    first = fill_defaults(schema, {}).arguments
    first["tags"].append("injected")
    assert schema["properties"]["tags"]["default"] == ["a"]
    assert fill_defaults(schema, {}).arguments["tags"] == ["a"]


def test_nested_defaults_are_left_alone() -> None:
    schema = {
        "properties": {
            "options": {"type": "object", "properties": {"depth": {"default": 3}}},
        }
    }
    assert fill_defaults(schema, {}).arguments == {}


@pytest.mark.parametrize(
    "schema",
    [
        None,
        "nonsense",
        {},
        {"properties": None},
        {"properties": ["path"]},
        {"properties": {"p": 1}},
    ],
)
def test_a_malformed_schema_fills_nothing_and_does_not_raise(schema: Any) -> None:
    filled = fill_defaults(schema, {"a": 1})
    assert filled.arguments == {"a": 1}
    assert filled.names == ()


# -- the stage ---------------------------------------------------------------------------------


def registry_with(schema: dict[str, Any]) -> ToolRegistry:
    registry = ToolRegistry()
    registry.replace({"files": (Tool(name="list_files", input_schema=schema),)})
    return registry


@pytest.mark.anyio
async def test_the_stage_fills_and_records_what_it_filled() -> None:
    ctx = RequestContext(method="tools/call", tool_name="files__list_files", arguments={})
    await ApplySchemaDefaults(registry_with(SCHEMA)).run(ctx)
    assert ctx.arguments == {"path": ".", "limit": 20}
    assert ctx.scan_flags[FLAG] == ["limit", "path"]


@pytest.mark.anyio
async def test_the_stage_leaves_no_flag_when_nothing_was_filled() -> None:
    ctx = RequestContext(
        method="tools/call", tool_name="files__list_files", arguments={"path": "a", "limit": 1}
    )
    await ApplySchemaDefaults(registry_with(SCHEMA)).run(ctx)
    assert FLAG not in ctx.scan_flags
    assert ctx.arguments == {"path": "a", "limit": 1}


@pytest.mark.anyio
async def test_the_stage_never_decides() -> None:
    """Deciding is policy's job; this stage only makes sure policy sees the real arguments."""
    ctx = RequestContext(method="tools/call", tool_name="files__list_files", arguments={})
    await ApplySchemaDefaults(registry_with(SCHEMA)).run(ctx)
    assert ctx.decision is not Decision.DENY


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# -- why reading the registry is safe ------------------------------------------------------------


def test_changing_only_a_default_changes_the_pin() -> None:
    """A rug pull that edits a default is a new definition, so it is quarantined first."""
    before = Tool(name="list_files", input_schema={"properties": {"path": {"default": "."}}})
    after = Tool(name="list_files", input_schema={"properties": {"path": {"default": "/"}}})
    assert definition_hash(before) != definition_hash(after)


def test_the_stage_sits_between_integrity_and_policy() -> None:
    """After `definitions`, so it reads only a pinned definition; before `policy`, so the
    constraints see what will be forwarded."""
    import inspect

    from warden.main import build_pipeline_factory

    source = inspect.getsource(build_pipeline_factory)
    order = source[source.index("return Pipeline(") :]
    assert order.index("definitions,") < order.index("defaults,") < order.index("policy,")
