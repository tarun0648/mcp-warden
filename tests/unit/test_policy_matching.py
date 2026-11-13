"""Glob semantics: a `*` must never cross the `__` separator."""

from __future__ import annotations

import pytest

from warden.policy.matching import matches, matches_any

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("pattern", "name"),
    [
        ("files__read_file", "files__read_file"),
        ("files__*", "files__read_file"),
        ("files__*", "files__delete_file"),
        ("files__read_*", "files__read_file"),
        ("notes_db__*", "notes_db__run_sql"),
        ("*__read_file", "files__read_file"),
        ("files__?ead_file", "files__read_file"),
        ("files__[rw]*", "files__read_file"),
    ],
)
def test_patterns_that_match(pattern: str, name: str) -> None:
    assert matches(pattern, name)


@pytest.mark.parametrize(
    ("pattern", "name"),
    [
        # The separator is a hard boundary: 'files' must be the whole server name.
        ("files__*", "files_x__read_file"),
        ("files__*", "filesx__read_file"),
        ("files__*", "notes_db__read_file"),
        ("files__read_*", "files__write_file"),
        ("files__read_file", "files__read_file_2"),
        # A pattern with no separator matches nothing, even one that looks total.
        ("*", "files__read_file"),
        ("files", "files__read_file"),
        ("read_file", "files__read_file"),
        # An unnamespaced name cannot be matched by a namespaced pattern.
        ("files__*", "read_file"),
        ("files__*", ""),
        # A tool glob does not reach into another server.
        ("notes_db__*", "notes_dbx__list"),
    ],
)
def test_patterns_that_do_not_match(pattern: str, name: str) -> None:
    assert not matches(pattern, name)


def test_a_star_in_the_server_position_still_stops_at_the_separator() -> None:
    """`*__delete_file` may match any server, but only the tool named delete_file."""
    assert matches("*__delete_file", "files__delete_file")
    assert matches("*__delete_file", "notes_db__delete_file")
    assert not matches("*__delete_file", "files__delete_file_now")


def test_matches_any() -> None:
    patterns = ["notes_db__list_notes", "files__read_*"]
    assert matches_any(patterns, "files__read_file")
    assert matches_any(patterns, "notes_db__list_notes")
    assert not matches_any(patterns, "files__write_file")
    assert not matches_any([], "files__read_file")
