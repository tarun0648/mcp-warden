"""A small notes MCP server: the benign upstream the gateway protects.

Tool descriptions here are short and honest on purpose. The gateway's definition scanner treats
every upstream description as untrusted data, and these are the negative examples that must not
be flagged.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from servers.notes_db.sql_guard import SqlNotAllowed
from servers.notes_db.store import NoteStore, NotFound

DEFAULT_DB_PATH = "./data/notes.sqlite3"


def database_path() -> Path:
    return Path(os.environ.get("NOTES_DB_PATH", DEFAULT_DB_PATH))


def build_server(store: NoteStore | None = None) -> MCPServer:
    """Create the notes server. Pass a `store` in tests to use a temporary database."""
    notes = store if store is not None else NoteStore(database_path())
    notes.initialise()

    server: MCPServer = MCPServer(
        name="notes_db",
        version="0.1.0",
        instructions="Read and write short text notes stored in a local SQLite database.",
    )

    @server.tool(description="List notes, oldest first.")
    def list_notes(
        limit: Annotated[int, Field(ge=1, le=200, description="How many notes to return.")] = 20,
    ) -> dict[str, Any]:
        return {"notes": [note.as_dict() for note in notes.list_notes(limit)]}

    @server.tool(description="Find notes whose title or body contains the given text.")
    def search_notes(
        query: Annotated[str, Field(min_length=1, max_length=200, description="Text to look for.")],
    ) -> dict[str, Any]:
        return {"notes": [note.as_dict() for note in notes.search_notes(query)]}

    @server.tool(description="Fetch one note by its id.")
    def get_note(
        note_id: Annotated[int, Field(ge=1, description="The note's id.")],
    ) -> dict[str, Any]:
        try:
            return notes.get_note(note_id).as_dict()
        except NotFound as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Create a note and return it.")
    def create_note(
        title: Annotated[str, Field(min_length=1, max_length=200, description="Note title.")],
        body: Annotated[str, Field(max_length=100_000, description="Note body text.")],
    ) -> dict[str, Any]:
        return notes.create_note(title, body).as_dict()

    @server.tool(description="Delete one note by its id. This cannot be undone.")
    def delete_note(
        note_id: Annotated[int, Field(ge=1, description="The note's id.")],
    ) -> dict[str, Any]:
        try:
            notes.delete_note(note_id)
        except NotFound as exc:
            raise ToolError(str(exc)) from exc
        return {"deleted": note_id}

    @server.tool(
        description=(
            "Run one read-only SELECT against the notes table and return the rows. "
            "Writes, PRAGMA, ATTACH and multiple statements are rejected."
        )
    )
    def run_sql(
        query: Annotated[
            str, Field(min_length=1, max_length=4000, description="A single SELECT statement.")
        ],
    ) -> dict[str, Any]:
        try:
            return notes.run_sql(query)
        except SqlNotAllowed as exc:
            raise ToolError(f"query rejected: {exc}") from exc

    return server


__all__ = ["DEFAULT_DB_PATH", "NoteStore", "build_server", "database_path"]
