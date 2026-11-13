"""The hash chain that makes the audit log tamper-evident.

Each row carries the previous row's hash, and its own hash covers every one of its own fields
*including* that link. So an attacker who edits one row has to recompute every row after it,
and an attacker who deletes or reorders a row leaves a link pointing at a hash that no longer
follows. `verify` walks the chain and names the first row that does not add up.

"Tamper-evident", not "tamper-proof": anyone who can write to the table and knows the scheme
can rebuild the whole chain. What this buys is that a *partial* edit - the realistic case, where
someone deletes the one row that incriminates them - cannot be hidden. Shipping the latest
`row_hash` somewhere the attacker does not control is what would close the gap, and that is
listed as a known gap in the threat model rather than claimed as solved.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

#: The `prev_hash` of the first row. Any value would do; a fixed one makes the first row's hash
#: reproducible, so even a chain of length one can be verified.
GENESIS_HASH: Final = "0" * 64

#: Every field covered by `row_hash`, in no particular order (the canonical form sorts them).
#: `row_hash` itself is excluded, because it is the output. `id` is excluded because the
#: database assigns it: including it would make a row's hash depend on a sequence value that a
#: restore or a failed insert can change without anyone tampering.
HASHED_FIELDS: Final[tuple[str, ...]] = (
    "ts",
    "request_id",
    "event",
    "principal_id",
    "auth_method",
    "method",
    "tool",
    "upstream",
    "risk",
    "args_redacted",
    "args_sha256",
    "decision",
    "reason_code",
    "matched_rule",
    "stage_timings_ms",
    "result_bytes",
    "result_sha256",
    "scan_flags",
    "prev_hash",
)


def canonical_json(value: Any) -> str:
    """A byte-identical rendering of `value`, whatever order its keys arrived in.

    Keys are sorted, separators are fixed, and datetimes become microsecond ISO-8601 in UTC.
    Without this, Postgres and SQLite - or two Python versions - could serialise the same row
    differently and every hash would disagree.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_encode,
    )


def _encode(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(tz=value.tzinfo).isoformat() if value.tzinfo else value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_arguments(arguments: dict[str, Any]) -> str:
    """The `args_sha256` of a call: a hash of the raw arguments, canonically rendered."""
    return sha256_text(canonical_json(arguments))


def row_payload(row: Any) -> dict[str, Any]:
    """The hashed fields of a row, read off either an ORM object or a plain mapping."""
    if isinstance(row, dict):
        source: dict[str, Any] = row
        return {field: source.get(field) for field in HASHED_FIELDS}
    return {field: getattr(row, field) for field in HASHED_FIELDS}


def compute_row_hash(row: Any) -> str:
    """`SHA-256(prev_hash || canonical JSON of the row without row_hash)`.

    `prev_hash` is hashed twice over - once as the prefix and once inside the payload - which
    costs nothing and means the link is covered even if a future change drops it from
    HASHED_FIELDS by accident.
    """
    payload = row_payload(row)
    prev = payload.get("prev_hash") or GENESIS_HASH
    return sha256_text(f"{prev}{canonical_json(payload)}")


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """Where and how the chain stops adding up."""

    row_id: int
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"row {self.row_id}: {self.kind} - {self.detail}"


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """The outcome of walking the chain."""

    ok: bool
    rows_checked: int
    first_break: ChainBreak | None = None
    #: The last row's hash, for anyone who wants to pin it somewhere external.
    head_hash: str = GENESIS_HASH

    def summary(self) -> str:
        if self.ok:
            return f"OK - {self.rows_checked} rows verified, head {self.head_hash[:16]}..."
        return f"BROKEN after {self.rows_checked} rows - {self.first_break}"


def verify_rows(rows: Sequence[Any], expected_prev: str = GENESIS_HASH) -> VerifyResult:
    """Walk rows in id order and report the first one that does not verify.

    `expected_prev` is the hash the first row must link to, so a long chain can be verified a
    page at a time by feeding each page the previous page's head.

    Two different failures are distinguished, because they mean different things to whoever is
    reading the report:

    * `row_hash` - this row's own contents were changed.
    * `prev_hash` - this row no longer follows the one before it, so a row between them was
      removed, reordered, or inserted.
    """
    checked = 0
    for row in rows:
        row_id = int(getattr(row, "id", 0) or (row.get("id", 0) if isinstance(row, dict) else 0))
        stored_prev = _field(row, "prev_hash") or GENESIS_HASH
        stored_hash = _field(row, "row_hash") or ""

        if stored_prev != expected_prev:
            return VerifyResult(
                ok=False,
                rows_checked=checked,
                first_break=ChainBreak(
                    row_id,
                    "prev_hash",
                    f"links to {stored_prev[:16]}... but the previous row hashes to "
                    f"{expected_prev[:16]}...; a row was removed, reordered or inserted",
                ),
                head_hash=expected_prev,
            )

        recomputed = compute_row_hash(row)
        if recomputed != stored_hash:
            return VerifyResult(
                ok=False,
                rows_checked=checked,
                first_break=ChainBreak(
                    row_id,
                    "row_hash",
                    f"stored {stored_hash[:16]}... but its contents hash to "
                    f"{recomputed[:16]}...; this row was edited",
                ),
                head_hash=expected_prev,
            )

        expected_prev = stored_hash
        checked += 1

    return VerifyResult(ok=True, rows_checked=checked, head_hash=expected_prev)


def _field(row: Any, name: str) -> Any:
    return row.get(name) if isinstance(row, dict) else getattr(row, name, None)


__all__ = [
    "GENESIS_HASH",
    "HASHED_FIELDS",
    "ChainBreak",
    "VerifyResult",
    "canonical_json",
    "compute_row_hash",
    "hash_arguments",
    "row_payload",
    "sha256_text",
    "verify_rows",
]
