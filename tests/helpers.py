"""Helpers for driving MCP servers from tests.

The SDK's client is an anyio context manager: entering it in a pytest async fixture and leaving
it in the fixture's finaliser crosses tasks, which anyio refuses. So tests enter the client
inside their own body with `async with notes_client(...)`, which keeps setup and teardown in one
task and keeps the lifetime visible in the test.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp import Client
from mcp_types import CallToolResult, TextContent


@asynccontextmanager
async def notes_client(tmp_path: Path) -> AsyncIterator[Client]:
    """A client connected in-process to a notes_db server with a temporary database."""
    from servers.notes_db import build_server
    from servers.notes_db.store import NoteStore

    store = NoteStore(tmp_path / "notes.sqlite3")
    async with Client(build_server(store)) as session:
        yield session


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
