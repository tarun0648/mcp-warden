"""Argument constraints: narrowing only, and no path trick gets past starts_with."""

from __future__ import annotations

from typing import Any

import pytest

from warden.config import ArgumentConstraint
from warden.policy.constraints import check_argument, check_constraints, normalise_path

pytestmark = pytest.mark.unit


def check(constraint: dict[str, Any], arguments: dict[str, Any], name: str = "path") -> str | None:
    """Returns None when the argument passes, else the failure message."""
    failure = check_argument(name, ArgumentConstraint(**constraint), arguments)
    return None if failure is None else str(failure)


# -- presence ----------------------------------------------------------------------------------


def test_a_missing_argument_fails_the_constraint() -> None:
    """A constraint implies the argument is required: the safe reading."""
    assert "not supplied" in (check({"max_length": 10}, {}) or "")


def test_an_optional_constraint_tolerates_absence() -> None:
    assert check({"max_length": 10, "optional": True}, {}) is None


# -- equals / in_list --------------------------------------------------------------------------


def test_equals() -> None:
    assert check({"equals": "a.md"}, {"path": "a.md"}) is None
    assert check({"equals": "a.md"}, {"path": "b.md"}) is not None


def test_in_list() -> None:
    constraint = {"in_list": ["a.md", "b.md"]}
    assert check(constraint, {"path": "a.md"}) is None
    assert check(constraint, {"path": "c.md"}) is not None


# -- numeric bounds ----------------------------------------------------------------------------


@pytest.mark.parametrize("value", [1, 50, 100, 1.5])
def test_numeric_bounds_accept_values_in_range(value: float) -> None:
    assert check({"min": 1, "max": 100}, {"path": value}) is None


@pytest.mark.parametrize("value", [0, 101, -5, 1000.1])
def test_numeric_bounds_reject_values_out_of_range(value: float) -> None:
    assert check({"min": 1, "max": 100}, {"path": value}) is not None


@pytest.mark.parametrize("value", ["50", None, [], {}, True])
def test_numeric_bounds_reject_non_numbers(value: Any) -> None:
    """A numeric *string* is refused: the upstream would parse it, we would not."""
    assert "must be a number" in (check({"min": 1, "max": 100}, {"path": value}) or "")


# -- max_length --------------------------------------------------------------------------------


def test_max_length_on_strings_lists_and_mappings() -> None:
    assert check({"max_length": 3}, {"path": "abc"}) is None
    assert check({"max_length": 3}, {"path": "abcd"}) is not None
    assert check({"max_length": 2}, {"path": [1, 2]}) is None
    assert check({"max_length": 1}, {"path": {"a": 1, "b": 2}}) is not None


def test_max_length_rejects_a_value_with_no_length() -> None:
    assert "to have a length" in (check({"max_length": 3}, {"path": 42}) or "")


# -- regex -------------------------------------------------------------------------------------


def test_regex_is_a_full_match_not_a_search() -> None:
    """A search would let `../../etc/passwd` through a pattern meant for `[a-z]+\\.md`."""
    constraint = {"regex": r"[a-z]+\.md"}
    assert check(constraint, {"path": "notes.md"}) is None
    assert check(constraint, {"path": "../notes.md"}) is not None
    assert check(constraint, {"path": "notes.md; rm -rf /"}) is not None


def test_regex_rejects_a_non_string() -> None:
    assert "must be a string" in (check({"regex": "[a-z]+"}, {"path": 7}) or "")


# -- starts_with (paths) -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["notes/a.md", "notes/deep/b.md", "notes", "./notes/a.md", "notes/./a.md"],
)
def test_starts_with_accepts_paths_inside_the_prefix(value: str) -> None:
    assert check({"starts_with": "notes/"}, {"path": value}) is None


@pytest.mark.parametrize(
    "value",
    [
        "notes/../secret",
        "notes/../../etc/passwd",
        "secret",
        "notesecret/a.md",
        "../notes/a.md",
        "/notes/a.md",
        "notes/../notes_private/x",
        "..",
    ],
)
def test_starts_with_rejects_everything_outside_the_prefix(value: str) -> None:
    """The comparison happens after normalisation, so `notes/../secret` is checked as `secret`."""
    assert check({"starts_with": "notes/"}, {"path": value}) is not None


def test_starts_with_compares_whole_segments() -> None:
    """A prefix of `notes` must not match `notesecret`, which a plain str.startswith would."""
    assert check({"starts_with": "notes"}, {"path": "notesecret/a.md"}) is not None
    assert check({"starts_with": "notes"}, {"path": "notes/a.md"}) is None


def test_starts_with_rejects_a_non_string() -> None:
    assert "checked as a path" in (check({"starts_with": "notes/"}, {"path": 1}) or "")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("notes/../secret", "secret"),
        ("./a.md", "a.md"),
        ("a//b", "a/b"),
        ("a/./b", "a/b"),
        (".", ""),
        ("notes\\a.md", "notes/a.md"),
        ("../x", "../x"),
    ],
)
def test_normalise_path(raw: str, expected: str) -> None:
    assert normalise_path(raw) == expected


# -- several constraints -----------------------------------------------------------------------


def test_all_constraints_must_hold() -> None:
    constraint = ArgumentConstraint(max_length=10, regex=r"[a-z/.]+", starts_with="notes/")
    assert check_argument("path", constraint, {"path": "notes/a.md"}) is None
    assert check_argument("path", constraint, {"path": "notes/AAA.md"}) is not None
    assert check_argument("path", constraint, {"path": "notes/averylongname.md"}) is not None


def test_check_constraints_reports_every_failure() -> None:
    failures = check_constraints(
        {
            "path": ArgumentConstraint(starts_with="notes/"),
            "limit": ArgumentConstraint(max=10),
        },
        {"path": "secret", "limit": 99},
    )
    assert {failure.argument for failure in failures} == {"path", "limit"}


def test_no_constraints_means_nothing_to_check() -> None:
    assert check_constraints({}, {"anything": "goes"}) == []
