"""notes_db exercised through a real MCP client session, not by calling Python functions."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from servers.notes_db.sql_guard import read_only_authorizer
from servers.notes_db.store import NoteStore

from tests.helpers import error_text, notes_client, payload

pytestmark = pytest.mark.integration


async def test_tools_list_exposes_the_six_tools(tmp_path: Path) -> None:
    async with notes_client(tmp_path) as client:
        listing = await client.list_tools()
    assert {tool.name for tool in listing.tools} == {
        "list_notes",
        "search_notes",
        "get_note",
        "create_note",
        "delete_note",
        "run_sql",
    }
    for tool in listing.tools:
        assert tool.description, f"{tool.name} has no description"


async def test_seeded_with_ten_notes(tmp_path: Path) -> None:
    async with notes_client(tmp_path) as client:
        result = await client.call_tool("list_notes", {"limit": 50})
    assert len(payload(result)["notes"]) == 10


async def test_crud_round_trip(tmp_path: Path) -> None:
    async with notes_client(tmp_path) as client:
        created = payload(await client.call_tool("create_note", {"title": "T", "body": "B"}))
        note_id = created["id"]
        fetched = payload(await client.call_tool("get_note", {"note_id": note_id}))
        assert fetched["title"] == "T" and fetched["body"] == "B"

        deleted = payload(await client.call_tool("delete_note", {"note_id": note_id}))
        assert deleted["deleted"] == note_id
        gone = await client.call_tool("get_note", {"note_id": note_id})
    assert "no note with id" in error_text(gone)


async def test_delete_unknown_note_is_a_clean_error(tmp_path: Path) -> None:
    async with notes_client(tmp_path) as client:
        result = await client.call_tool("delete_note", {"note_id": 9999})
    assert "no note with id 9999" in error_text(result)


async def test_search_finds_notes(tmp_path: Path) -> None:
    async with notes_client(tmp_path) as client:
        found = payload(await client.call_tool("search_notes", {"query": "password"}))["notes"]
    assert len(found) == 1
    assert found[0]["title"] == "Password policy"


async def test_search_is_not_sql_injectable(tmp_path: Path) -> None:
    """A classic injection payload must be treated as literal search text."""
    async with notes_client(tmp_path) as client:
        before = payload(await client.call_tool("list_notes", {"limit": 50}))["notes"]
        result = await client.call_tool("search_notes", {"query": "x' OR '1'='1"})
        assert payload(result)["notes"] == []
        after = payload(await client.call_tool("list_notes", {"limit": 50}))["notes"]
    assert len(after) == len(before), "the table must be untouched"


async def test_search_escapes_like_wildcards(tmp_path: Path) -> None:
    """'%' is searched for literally, so it must not match every note."""
    async with notes_client(tmp_path) as client:
        result = await client.call_tool("search_notes", {"query": "%"})
    assert payload(result)["notes"] == []


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("list_notes", {"limit": 0}),
        ("list_notes", {"limit": 10_000}),
        ("get_note", {"note_id": 0}),
        ("create_note", {"title": "", "body": "x"}),
        ("search_notes", {"query": ""}),
    ],
)
async def test_input_validation_rejects_out_of_range(
    tmp_path: Path, tool: str, args: dict[str, object]
) -> None:
    async with notes_client(tmp_path) as client:
        result = await client.call_tool(tool, args)
    assert result.is_error, f"{tool}{args} should have been rejected"


async def test_run_sql_allows_a_plain_select(tmp_path: Path) -> None:
    async with notes_client(tmp_path) as client:
        result = payload(
            await client.call_tool("run_sql", {"query": "SELECT id, title FROM notes"})
        )
    assert result["columns"] == ["id", "title"]
    assert result["row_count"] == 10


async def test_run_sql_allows_a_read_only_cte(tmp_path: Path) -> None:
    query = "WITH recent AS (SELECT id FROM notes WHERE id > 5) SELECT COUNT(*) AS n FROM recent"
    async with notes_client(tmp_path) as client:
        result = payload(await client.call_tool("run_sql", {"query": query}))
    assert result["rows"] == [[5]]


@pytest.mark.parametrize(
    ("query", "expect"),
    [
        ("DROP TABLE notes", "drop"),
        ("INSERT INTO notes (title, body) VALUES ('a','b')", "insert"),
        ("UPDATE notes SET title = 'x'", "update"),
        ("DELETE FROM notes", "delete"),
        ("SELECT 1; DROP TABLE notes", "only one statement"),
        ("SELECT 1;DROP TABLE notes;", "only one statement"),
        ("ATTACH DATABASE '/etc/passwd' AS evil", "attach"),
        ("PRAGMA table_info(notes)", "pragma"),
        ("WITH x AS (DELETE FROM notes RETURNING id) SELECT * FROM x", "delete"),
        ("WITH x AS (SELECT 1) DELETE FROM notes", "delete"),
        ("VACUUM", "vacuum"),
        ("CREATE TABLE t (a INT)", "create"),
        ("SELECT load_extension('/tmp/x.so')", "load_extension"),
        ("EXPLAIN SELECT 1", "must be a single select"),
    ],
)
async def test_run_sql_rejects_unsafe_statements(tmp_path: Path, query: str, expect: str) -> None:
    async with notes_client(tmp_path) as client:
        result = await client.call_tool("run_sql", {"query": query})
    assert result.is_error, f"{query!r} should have been rejected"
    assert expect in error_text(result).lower()


async def test_run_sql_rejects_an_empty_query_at_the_schema(tmp_path: Path) -> None:
    async with notes_client(tmp_path) as client:
        assert (await client.call_tool("run_sql", {"query": ""})).is_error
        assert (await client.call_tool("run_sql", {"query": "   "})).is_error


@pytest.mark.parametrize(
    "query",
    [
        # A keyword inside a comment is inert: SQLite stops reading the line at '--', and our
        # single-statement check runs on a copy with comments removed.
        "SELECT 1 -- ; DROP TABLE notes",
        # 'created' must not be mistaken for the CREATE keyword.
        "SELECT id, created FROM notes WHERE id = 1",
    ],
)
async def test_run_sql_allows_queries_that_only_look_dangerous(tmp_path: Path, query: str) -> None:
    async with notes_client(tmp_path) as client:
        result = await client.call_tool("run_sql", {"query": query})
    assert not result.is_error, error_text(result)


async def test_run_sql_treats_keywords_inside_literals_as_text(tmp_path: Path) -> None:
    """A literal containing 'drop table' is fine; only real SQL keywords are refused."""
    async with notes_client(tmp_path) as client:
        result = await client.call_tool(
            "run_sql", {"query": "SELECT id FROM notes WHERE body LIKE '%drop table%'"}
        )
    assert payload(result)["row_count"] == 0


def test_read_only_connection_refuses_writes(tmp_path: Path) -> None:
    """The layers behind the parser: a read-only URI plus a deny-by-default authorizer."""
    store = NoteStore(tmp_path / "notes.sqlite3")
    store.initialise()
    conn = sqlite3.connect(f"file:{store.path}?mode=ro", uri=True)
    conn.set_authorizer(read_only_authorizer)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM notes")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("PRAGMA table_info(notes)")
    finally:
        conn.set_authorizer(None)
        conn.close()
    assert len(store.list_notes(50)) == 10
