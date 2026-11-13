"""The hash chain: canonical rendering, row hashing, and what verify can detect."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from warden.audit.chain import (
    GENESIS_HASH,
    HASHED_FIELDS,
    canonical_json,
    compute_row_hash,
    hash_arguments,
    row_payload,
    verify_rows,
)

pytestmark = pytest.mark.unit


def row(index: int, prev_hash: str, **overrides: Any) -> dict[str, Any]:
    """A plain-dict stand-in for an AuditEvent row."""
    base: dict[str, Any] = {
        "id": index,
        "ts": datetime(2026, 11, 13, 12, 0, 0, tzinfo=UTC) + timedelta(seconds=index),
        "request_id": f"req{index}",
        "event": "finished",
        "principal_id": "alice",
        "auth_method": "api_key",
        "method": "tools/call",
        "tool": "files__read_file",
        "upstream": "files",
        "risk": "read",
        "args_redacted": {"path": "a.md"},
        "args_sha256": "a" * 64,
        "decision": "allow",
        "reason_code": "WARDEN_ALLOWED",
        "matched_rule": "editor-files-read",
        "stage_timings_ms": {"policy": 0.5},
        "result_bytes": 12,
        "result_sha256": "b" * 64,
        "scan_flags": {},
        "prev_hash": prev_hash,
    }
    base.update(overrides)
    base["row_hash"] = compute_row_hash(base)
    return base


def chain(length: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    prev = GENESIS_HASH
    for index in range(1, length + 1):
        current = row(index, prev)
        rows.append(current)
        prev = current["row_hash"]
    return rows


# -- canonical rendering -----------------------------------------------------------------------


def test_key_order_does_not_change_the_rendering() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_rendering_is_stable_across_nesting() -> None:
    left = {"outer": {"z": [1, {"b": 2, "a": 3}]}}
    right = {"outer": {"z": [1, {"a": 3, "b": 2}]}}
    assert canonical_json(left) == canonical_json(right)


def test_datetimes_render_as_iso_with_microseconds() -> None:
    moment = datetime(2026, 11, 13, 12, 0, 0, 123456, tzinfo=UTC)
    assert "2026-11-13T12:00:00.123456" in canonical_json({"ts": moment})


def test_non_ascii_survives() -> None:
    assert "café" in canonical_json({"note": "café"})


def test_hash_arguments_is_order_independent() -> None:
    assert hash_arguments({"a": 1, "b": 2}) == hash_arguments({"b": 2, "a": 1})


def test_hash_arguments_distinguishes_different_arguments() -> None:
    assert hash_arguments({"path": "a.md"}) != hash_arguments({"path": "b.md"})


def test_the_argument_hash_is_not_the_arguments() -> None:
    """The hash is stored instead of the values, so it must not contain them."""
    digest = hash_arguments({"password": "hunter2"})
    assert "hunter2" not in digest
    assert len(digest) == 64


# -- row hashing -------------------------------------------------------------------------------


def test_row_hash_covers_every_hashed_field() -> None:
    """If a field were left out of the hash, it could be edited undetectably."""
    original = row(1, GENESIS_HASH)
    for field in HASHED_FIELDS:
        tampered = dict(original)
        tampered[field] = _mutate(original[field])
        assert compute_row_hash(tampered) != original["row_hash"], (
            f"editing '{field}' did not change the row hash"
        )


def _mutate(value: Any) -> Any:
    if isinstance(value, str):
        return value + "x"
    if isinstance(value, int):
        return value + 1
    if isinstance(value, dict):
        return {**value, "injected": True}
    if isinstance(value, datetime):
        return value.replace(year=2027)
    if value is None:
        return "no-longer-null"
    return "changed"


def test_row_hash_excludes_id_and_row_hash() -> None:
    """The id is assigned by the database; a restore or a burnt sequence value must not look
    like tampering."""
    assert "id" not in row_payload(row(1, GENESIS_HASH))
    assert "row_hash" not in row_payload(row(1, GENESIS_HASH))
    first = row(1, GENESIS_HASH)
    renumbered = {**first, "id": 999}
    assert compute_row_hash(renumbered) == first["row_hash"]


def test_identical_content_in_different_positions_hashes_differently() -> None:
    """Because prev_hash is part of the payload, a replayed row does not fit elsewhere."""
    first = row(1, GENESIS_HASH)
    second = row(1, first["row_hash"])
    assert first["row_hash"] != second["row_hash"]


# -- verification ------------------------------------------------------------------------------


def test_an_empty_chain_verifies() -> None:
    result = verify_rows([])
    assert result.ok and result.rows_checked == 0 and result.head_hash == GENESIS_HASH


def test_a_clean_chain_verifies() -> None:
    rows = chain(25)
    result = verify_rows(rows)
    assert result.ok
    assert result.rows_checked == 25
    assert result.head_hash == rows[-1]["row_hash"]


def test_an_edited_row_is_detected_and_named() -> None:
    rows = chain(10)
    rows[4]["decision"] = "allow-but-actually-not"
    result = verify_rows(rows)
    assert not result.ok
    assert result.first_break is not None
    assert result.first_break.row_id == 5
    assert result.first_break.kind == "row_hash"
    assert "edited" in result.first_break.detail
    assert result.rows_checked == 4, "the first four rows did verify"


def test_an_edited_row_that_is_rehashed_still_breaks_the_next_link() -> None:
    """The realistic attempt: edit a row and recompute *its* hash, forgetting the rest."""
    rows = chain(10)
    rows[4]["reason_code"] = "WARDEN_ALLOWED"
    rows[4]["decision"] = "allow"
    rows[4]["tool"] = "files__delete_file"
    rows[4]["row_hash"] = compute_row_hash(rows[4])
    result = verify_rows(rows)
    assert not result.ok
    assert result.first_break is not None
    assert result.first_break.row_id == 6, "the break shows up at the row that follows"
    assert result.first_break.kind == "prev_hash"


def test_a_deleted_row_is_detected() -> None:
    rows = chain(10)
    del rows[5]
    result = verify_rows(rows)
    assert not result.ok
    assert result.first_break is not None
    assert result.first_break.row_id == 7
    assert result.first_break.kind == "prev_hash"
    assert "removed, reordered or inserted" in result.first_break.detail


def test_a_deleted_last_row_is_not_detectable_by_the_chain_alone() -> None:
    """An honest limit: truncating the tail leaves a shorter but internally consistent chain.

    This is why `warden audit verify` prints the head hash: pinning it somewhere the gateway
    cannot write is what detects truncation. Recorded as a known gap in the threat model.
    """
    rows = chain(10)
    truncated = rows[:-1]
    assert verify_rows(truncated).ok
    assert verify_rows(truncated).head_hash != verify_rows(rows).head_hash


def test_a_reordered_pair_is_detected() -> None:
    rows = chain(10)
    rows[3], rows[4] = rows[4], rows[3]
    result = verify_rows(rows)
    assert not result.ok
    assert result.first_break is not None
    assert result.first_break.kind == "prev_hash"


def test_an_inserted_row_is_detected() -> None:
    rows = chain(10)
    forged = row(99, rows[4]["row_hash"], tool="files__delete_file", decision="allow")
    rows.insert(5, forged)
    result = verify_rows(rows)
    assert not result.ok
    assert result.first_break is not None
    # The forged row itself links correctly; the row after it no longer does.
    assert result.first_break.row_id == 6
    assert result.first_break.kind == "prev_hash"


def test_a_chain_whose_first_row_does_not_start_at_genesis_is_detected() -> None:
    rows = chain(3)
    rows[0]["prev_hash"] = "f" * 64
    rows[0]["row_hash"] = compute_row_hash(rows[0])
    result = verify_rows(rows)
    assert not result.ok
    assert result.first_break is not None
    assert result.first_break.row_id == 1


def test_verification_can_resume_from_a_known_head() -> None:
    """How a long chain is verified a page at a time."""
    rows = chain(10)
    first_page = verify_rows(rows[:4])
    assert first_page.ok
    second_page = verify_rows(rows[4:], first_page.head_hash)
    assert second_page.ok
    assert second_page.head_hash == rows[-1]["row_hash"]


def test_resuming_from_the_wrong_head_fails() -> None:
    rows = chain(10)
    assert not verify_rows(rows[4:], "0" * 63 + "1").ok


@given(
    length=st.integers(min_value=1, max_value=30),
    target=st.integers(min_value=0, max_value=29),
)
def test_editing_any_single_row_is_always_detected(length: int, target: int) -> None:
    """The property the whole design rests on."""
    rows = chain(length)
    index = target % length
    rows[index]["tool"] = "files__delete_file"
    result = verify_rows(rows)
    assert not result.ok
    assert result.first_break is not None
    assert result.first_break.row_id == rows[index]["id"]


@given(length=st.integers(min_value=2, max_value=30), target=st.integers(0, 28))
def test_deleting_any_non_final_row_is_always_detected(length: int, target: int) -> None:
    rows = chain(length)
    index = target % (length - 1)
    del rows[index]
    assert not verify_rows(rows).ok
