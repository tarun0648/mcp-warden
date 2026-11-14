"""Checking one call's arguments against a rule's argument constraints.

Two rules govern everything here:

1. A constraint can only ever *narrow* access. A missing argument, a wrongly typed argument or
   an unparseable one fails the constraint, which means the allow rule does not apply.
2. Paths are compared after normalisation, so `notes/../secret` is checked as `secret` and
   cannot pass a `starts_with: notes/` constraint.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Final

from warden.config import ArgumentConstraint


@dataclass(frozen=True, slots=True)
class ConstraintFailure:
    """Why one argument failed, in words an operator and a model can both read."""

    argument: str
    problem: str

    def __str__(self) -> str:
        return f"argument '{self.argument}' {self.problem}"


#: Any percent-encoded byte. Mirrors `servers.files.safe_path.PERCENT_ENCODING_RE`; the two
#: are deliberately the same rule applied at two layers.
PERCENT_ENCODING_RE: Final = re.compile(r"%[0-9A-Fa-f]{2}")


@lru_cache(maxsize=1024)
def _compiled(pattern: str) -> re.Pattern[str]:
    """Compile a policy regex once. Patterns are checked for safety at config load time."""
    return re.compile(pattern)


def normalise_path(value: str) -> str:
    """The path a `starts_with` constraint is compared against.

    Collapses `.`, resolves `..` textually and strips a leading `./`. An argument that climbs
    above the root normalises to something starting with `..`, which no sane prefix matches.
    """
    collapsed = posixpath.normpath(value.replace("\\", "/"))
    return "" if collapsed == "." else collapsed


def check_argument(
    name: str, constraint: ArgumentConstraint, arguments: dict[str, Any]
) -> ConstraintFailure | None:
    """Check one argument. Returns None when it passes, or the reason it did not."""
    if name not in arguments:
        if constraint.optional:
            return None
        return ConstraintFailure(name, "is required by the policy but was not supplied")
    value = arguments[name]

    if constraint.equals is not None and value != constraint.equals:
        return ConstraintFailure(name, f"must equal {constraint.equals!r}")

    if constraint.in_list is not None and value not in constraint.in_list:
        return ConstraintFailure(name, "is not one of the allowed values")

    if constraint.min is not None or constraint.max is not None:
        number = _as_number(value)
        if number is None:
            return ConstraintFailure(name, "must be a number")
        if constraint.min is not None and number < constraint.min:
            return ConstraintFailure(name, f"must be at least {constraint.min:g}")
        if constraint.max is not None and number > constraint.max:
            return ConstraintFailure(name, f"must be at most {constraint.max:g}")

    if constraint.max_length is not None:
        length = _length_of(value)
        if length is None:
            return ConstraintFailure(name, "must be a string, list or mapping to have a length")
        if length > constraint.max_length:
            return ConstraintFailure(
                name, f"is {length} long, over the limit of {constraint.max_length}"
            )

    if constraint.regex is not None:
        if not isinstance(value, str):
            return ConstraintFailure(name, "must be a string to be matched against a pattern")
        if not _compiled(constraint.regex).fullmatch(value):
            return ConstraintFailure(name, "does not match the allowed pattern")

    if constraint.starts_with is not None:
        if not isinstance(value, str):
            return ConstraintFailure(name, "must be a string to be checked as a path")
        if PERCENT_ENCODING_RE.search(value):
            # Found by the red-team suite: "%2e%2e/%2e%2e/etc/passwd" normalises to itself, so
            # a prefix check passes it and only the upstream's own sandbox stops it. The files
            # server refuses percent-encoding outright, and the gateway now says the same -
            # decoding is what turns these into traversal, and a path constraint that depends on
            # the upstream agreeing with it is one layer, not two.
            return ConstraintFailure(
                name, "must not contain percent-encoding, which is not accepted in a path"
            )
        candidate = normalise_path(value)
        prefix = normalise_path(constraint.starts_with)
        if not _path_within(candidate, prefix):
            return ConstraintFailure(
                name, f"must be inside '{constraint.starts_with}' (checked after normalisation)"
            )

    return None


def _path_within(candidate: str, prefix: str) -> bool:
    """True when the normalised `candidate` is `prefix` itself or sits under it.

    Compared segment by segment, so a prefix of `notes` does not match `notesecret`.
    """
    if candidate.startswith("..") or candidate.startswith("/") != prefix.startswith("/"):
        return False
    if prefix in ("", "."):
        return True
    candidate_parts = [part for part in candidate.split("/") if part]
    prefix_parts = [part for part in prefix.split("/") if part]
    return candidate_parts[: len(prefix_parts)] == prefix_parts


def _as_number(value: Any) -> float | None:
    """Numbers only. A numeric string is deliberately not accepted: a policy that compares a
    string to a bound would be comparing something the upstream will parse differently."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def _length_of(value: Any) -> int | None:
    if isinstance(value, str | list | dict | tuple):
        return len(value)
    return None


def check_constraints(
    constraints: dict[str, ArgumentConstraint], arguments: dict[str, Any]
) -> list[ConstraintFailure]:
    """Check every constraint and return all failures, so a caller sees the whole problem."""
    failures = [
        failure
        for name, constraint in constraints.items()
        if (failure := check_argument(name, constraint, arguments)) is not None
    ]
    return failures


__all__ = [
    "PERCENT_ENCODING_RE",
    "ConstraintFailure",
    "check_argument",
    "check_constraints",
    "normalise_path",
]
