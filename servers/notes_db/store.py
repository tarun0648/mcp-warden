"""SQLite storage for the notes server. All queries are parameterised."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from servers.notes_db.sql_guard import (
    MAX_ROWS,
    read_only_authorizer,
    validate_read_only_sql,
)

SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS notes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    title   TEXT NOT NULL,
    body    TEXT NOT NULL,
    created TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

SEED_NOTES: Final[tuple[tuple[str, str], ...]] = (
    ("Project kickoff", "We agreed to ship the gateway in phases. Phase 0 is the scaffold."),
    ("Password policy", "Rotate credentials every 90 days and never paste them into chat."),
    (
        "Standup 2026-11-02",
        "Blocked on the upstream reconnect loop; ignore the flaky test for now.",
    ),
    ("Groceries", "Oat milk, rye bread, tomatoes, coffee beans."),
    ("Reading list", "The Pragmatic Programmer, Designing Data-Intensive Applications."),
    ("Interview prep", "Be able to explain the pipeline order and why each stage fails closed."),
    ("Bug 412", "Traversal attempt in the files server returned a stack trace. Fixed."),
    ("Travel notes", "Flight lands 18:40; the hotel holds the room until 21:00."),
    ("Ideas", "A system that summarises my notes each Sunday evening."),
    ("Retro actions", "Write the threat model before adding more scanners."),
)


class NotFound(LookupError):
    """No note with that id."""


@dataclass(frozen=True, slots=True)
class Note:
    id: int
    title: str
    body: str
    created: str

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "body": self.body, "created": self.created}


class NoteStore:
    """Read/write access to the notes database, plus a strictly read-only SQL escape hatch."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def initialise(self, *, seed: bool = True) -> None:
        """Create the schema and, on an empty database, insert the seed notes."""
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            if seed and conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 0:
                conn.executemany("INSERT INTO notes (title, body) VALUES (?, ?)", list(SEED_NOTES))

    def list_notes(self, limit: int) -> list[Note]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, title, body, created FROM notes ORDER BY id LIMIT ?", (limit,)
            ).fetchall()
        return [Note(**dict(row)) for row in rows]

    def search_notes(self, query: str, limit: int = 50) -> list[Note]:
        """Case-insensitive substring search. The pattern is bound, never formatted in."""
        # Escape the LIKE wildcards so a query of "100%" searches for that text, not a prefix.
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, title, body, created FROM notes "
                "WHERE title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\' "
                "ORDER BY id LIMIT ?",
                (pattern, pattern, limit),
            ).fetchall()
        return [Note(**dict(row)) for row in rows]

    def get_note(self, note_id: int) -> Note:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id, title, body, created FROM notes WHERE id = ?", (note_id,)
            ).fetchone()
        if row is None:
            raise NotFound(f"no note with id {note_id}")
        return Note(**dict(row))

    def create_note(self, title: str, body: str) -> Note:
        with self.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO notes (title, body) VALUES (?, ?) RETURNING id, title, body, created",
                (title, body),
            )
            row = cursor.fetchone()
        return Note(**dict(row))

    def delete_note(self, note_id: int) -> None:
        with self.connect() as conn:
            cursor = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
            if cursor.rowcount == 0:
                raise NotFound(f"no note with id {note_id}")

    def run_sql(self, query: str) -> dict[str, Any]:
        """Run exactly one read-only SELECT and return its rows.

        Validated by `validate_read_only_sql`, executed on a read-only connection, and guarded
        by an authorizer that denies anything but reads.
        """
        statement = validate_read_only_sql(query)
        uri = f"file:{self.path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.set_authorizer(read_only_authorizer)
            cursor = conn.execute(statement)
            rows = cursor.fetchmany(MAX_ROWS)
            columns = [description[0] for description in (cursor.description or [])]
        finally:
            conn.set_authorizer(None)
            conn.close()
        return {
            "columns": columns,
            "rows": [list(row) for row in rows],
            "row_count": len(rows),
            "truncated": len(rows) == MAX_ROWS,
        }
