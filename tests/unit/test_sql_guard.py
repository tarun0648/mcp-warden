"""Unit tests for the SQL guard's own logic, independent of the server."""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st
from servers.notes_db.sql_guard import SqlNotAllowed, strip_sql_noise, validate_read_only_sql

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("raw", "expect"),
    [
        ("SELECT 1 -- comment", "SELECT 1 "),
        ("SELECT /* mid */ 1", "SELECT  1"),
        ("SELECT 'drop table'", "SELECT  "),
        ('SELECT "col"', "SELECT  "),
        ("SELECT [weird name]", "SELECT          "),
        ("SELECT 'it''s'", "SELECT      "),
    ],
)
def test_strip_sql_noise(raw: str, expect: str) -> None:
    assert strip_sql_noise(raw).rstrip(" ") == expect.rstrip(" ")


def test_unterminated_bracket_identifier_is_rejected() -> None:
    with pytest.raises(SqlNotAllowed):
        strip_sql_noise("SELECT [oops")


@pytest.mark.parametrize(
    "query",
    [
        "SELECT * FROM notes",
        "select id from notes where id = 1",
        "WITH t AS (SELECT 1 AS n) SELECT n FROM t",
        "SELECT COUNT(*) FROM notes;",
        "SELECT group_concat(title) FROM notes",
    ],
)
def test_accepts_read_only_selects(query: str) -> None:
    assert validate_read_only_sql(query)


@pytest.mark.parametrize(
    "query",
    [
        "DROP TABLE notes",
        "SELECT 1; SELECT 2",
        "ATTACH '/tmp/x' AS y",
        "pragma journal_mode",
        "WITH t AS (SELECT 1) INSERT INTO notes VALUES (1,'a','b','c')",
        "\x00SELECT 1",
        "x" * 5000,
        "WITH t AS (SELECT 1)",
    ],
)
def test_rejects_everything_else(query: str) -> None:
    with pytest.raises(SqlNotAllowed):
        validate_read_only_sql(query)


@given(st.text(max_size=200))
def test_never_raises_an_unexpected_exception(query: str) -> None:
    """Any input is either accepted or refused with SqlNotAllowed; nothing else escapes."""
    with contextlib.suppress(SqlNotAllowed):
        validate_read_only_sql(query)
