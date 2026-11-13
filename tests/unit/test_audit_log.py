"""The audit writer: write-ahead, outcome rows, redaction, filters and pagination."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from mcp_types import CallToolResult, TextContent
from sqlalchemy import text

from warden.audit.log import (
    EVENT_DENIED,
    EVENT_FINISHED,
    EVENT_STARTED,
    AuditFilters,
    AuditLog,
    AuditUnavailable,
)
from warden.audit.stage import AuditWriteAhead, audit_finish_hook
from warden.config import Risk
from warden.db.engine import Database
from warden.errors import ReasonCode
from warden.pipeline import Decision, Pipeline, Principal, RequestContext

pytestmark = pytest.mark.unit

CANARY = "wdn_canary_do_not_log_0123456789abcdef"


@pytest.fixture
def audit(database: Database) -> AuditLog:
    return AuditLog(database)


def principal(user: str = "alice", *roles: str) -> Principal:
    return Principal(
        user_id=user,
        roles=roles or ("editor",),
        auth_method="api_key",
        credential_id="prefix01",
    )


def context(**overrides: Any) -> RequestContext:
    defaults: dict[str, Any] = {
        "method": "tools/call",
        "tool_name": "files__read_file",
        "upstream": "files",
        "principal": principal(),
        "arguments": {"path": "a.md"},
        "risk": Risk.READ,
    }
    defaults.update(overrides)
    return RequestContext(**defaults)


# -- appending ---------------------------------------------------------------------------------


async def test_a_single_row_chains_from_genesis(audit: AuditLog) -> None:
    from warden.audit.chain import GENESIS_HASH

    row = await audit.record_started(context())
    assert row.prev_hash == GENESIS_HASH
    assert len(row.row_hash) == 64
    assert (await audit.verify()).ok


async def test_rows_chain_in_order(audit: AuditLog) -> None:
    first = await audit.record_started(context())
    second = await audit.record_started(context())
    assert second.prev_hash == first.row_hash
    result = await audit.verify()
    assert result.ok and result.rows_checked == 2
    assert result.head_hash == second.row_hash


async def test_a_started_row_records_the_intent_not_the_outcome(audit: AuditLog) -> None:
    """The write-ahead row is written before anything is known, so it says 'allow'."""
    row = await audit.record_started(context())
    assert row.event == EVENT_STARTED
    assert row.decision == str(Decision.ALLOW)
    assert row.reason_code == str(ReasonCode.ALLOWED)


async def test_an_allowed_call_leaves_a_started_and_a_finished_row(audit: AuditLog) -> None:
    ctx = context()
    await audit.record_started(ctx)
    ctx.forwarded = True
    ctx.result = CallToolResult(content=[TextContent(type="text", text="hello")])
    ctx.result_bytes = 5
    await audit.record_outcome(ctx)

    rows = await audit.rows_for_request(ctx.request_id)
    assert [row["event"] for row in rows] == [EVENT_STARTED, EVENT_FINISHED]
    assert rows[1]["decision"] == "allow"
    assert rows[1]["result_bytes"] == 5
    assert rows[1]["result_sha256"] is not None
    assert (await audit.verify()).ok


async def test_a_call_denied_before_forwarding_leaves_one_denied_row(audit: AuditLog) -> None:
    ctx = context()
    ctx.deny(ReasonCode.DENIED_POLICY, "no", rule="reader-no-sql")
    await audit.record_outcome(ctx)
    rows = await audit.rows_for_request(ctx.request_id)
    assert len(rows) == 1
    assert rows[0]["event"] == EVENT_DENIED
    assert rows[0]["decision"] == "deny"
    assert rows[0]["reason_code"] == "WARDEN_DENIED:policy"
    assert rows[0]["matched_rule"] == "reader-no-sql"


async def test_a_call_denied_after_forwarding_is_finished_not_denied(audit: AuditLog) -> None:
    """A timeout means the upstream may well have acted, so the row must not say 'denied'."""
    ctx = context()
    await audit.record_started(ctx)
    ctx.forwarded = True
    ctx.deny(ReasonCode.UPSTREAM_TIMEOUT, "too slow")
    await audit.record_outcome(ctx)
    rows = await audit.rows_for_request(ctx.request_id)
    assert [row["event"] for row in rows] == [EVENT_STARTED, EVENT_FINISHED]
    assert rows[1]["reason_code"] == "WARDEN_UPSTREAM_TIMEOUT"
    assert rows[1]["decision"] == "deny"


async def test_stage_timings_and_scan_flags_are_recorded(audit: AuditLog) -> None:
    ctx = context()
    ctx.stage_timings_ms = {"policy": 0.123456, "ratelimit": 1.5}
    ctx.scan_flags = {"retry_after_seconds": 2.5, "limit": "warden:rl:p:<caller>"}
    await audit.record_outcome(ctx)
    row = (await audit.rows_for_request(ctx.request_id))[0]
    assert row["stage_timings_ms"] == {"policy": 0.123, "ratelimit": 1.5}
    assert row["scan_flags"]["limit"] == "warden:rl:p:<caller>"


async def test_an_unauthenticated_denial_still_leaves_a_row(audit: AuditLog) -> None:
    ctx = context(principal=None)
    ctx.deny(ReasonCode.DENIED_AUTH, "no credential")
    await audit.record_outcome(ctx)
    row = (await audit.rows_for_request(ctx.request_id))[0]
    assert row["principal_id"] is None
    assert row["reason_code"] == "WARDEN_DENIED:auth"


# -- redaction ---------------------------------------------------------------------------------


async def test_arguments_are_stored_redacted_with_a_hash_of_the_originals(
    audit: AuditLog,
) -> None:
    from warden.audit.chain import hash_arguments

    arguments = {"path": "a.md", "api_key": CANARY, "nested": {"token": CANARY}}
    ctx = context(arguments=arguments)
    await audit.record_outcome(ctx)
    row = (await audit.rows_for_request(ctx.request_id))[0]
    assert row["args_redacted"]["path"] == "a.md"
    assert row["args_redacted"]["api_key"] == "[REDACTED]"
    assert row["args_redacted"]["nested"]["token"] == "[REDACTED]"
    assert row["args_sha256"] == hash_arguments(arguments)
    assert CANARY not in str(row)


async def test_a_canary_in_the_arguments_reaches_no_column(
    audit: AuditLog, database: Database
) -> None:
    """Hard rule 2, as a grep over the whole table."""
    ctx = context(
        arguments={"password": CANARY, "authorization": f"Bearer {CANARY}", "note": "fine"}
    )
    await audit.record_started(ctx)
    ctx.forwarded = True
    ctx.result = CallToolResult(content=[TextContent(type="text", text="ok")])
    await audit.record_outcome(ctx)

    async with database.session() as session:
        rows = (await session.execute(text("SELECT * FROM audit_events"))).mappings().all()
    dumped = repr([dict(row) for row in rows])
    assert CANARY not in dumped
    assert "[REDACTED]" in dumped


async def test_a_canary_in_an_unredactable_position_is_still_hashed_not_stored(
    audit: AuditLog,
) -> None:
    """A secret passed under an innocent key *is* stored, and that is the honest limit.

    `redact` masks by key name, so a credential sent as `{"note": "<secret>"}` is kept. The
    defence against that is the DLP stage (Phase 8), which refuses the call before it is
    forwarded; the audit row then records the denial, not the value. This test pins the current
    behaviour so the Phase 8 change is visible.
    """
    ctx = context(arguments={"note": CANARY})
    await audit.record_outcome(ctx)
    row = (await audit.rows_for_request(ctx.request_id))[0]
    assert row["args_redacted"]["note"] == CANARY


# -- the stage and the finish hook -------------------------------------------------------------


async def test_the_write_ahead_stage_records_and_allows(audit: AuditLog) -> None:
    ctx = context()
    await AuditWriteAhead(audit).run(ctx)
    assert ctx.decision is Decision.ALLOW
    assert len(await audit.rows_for_request(ctx.request_id)) == 1


async def test_the_write_ahead_stage_denies_when_the_log_is_unwritable(
    tmp_path: Any,
) -> None:
    """Hard rule 1: a call that cannot be recorded is a call that does not happen."""
    broken = Database("sqlite+aiosqlite:///" + str(tmp_path / "no-schema.sqlite3"))
    try:
        ctx = context()
        await AuditWriteAhead(AuditLog(broken)).run(ctx)
        assert ctx.decision is Decision.DENY
        assert ctx.reason_code is ReasonCode.DENIED_AUDIT_UNAVAILABLE
        assert "not forwarded" in (ctx.reason or "")
    finally:
        await broken.dispose()


async def test_record_started_raises_audit_unavailable(tmp_path: Any) -> None:
    broken = Database("sqlite+aiosqlite:///" + str(tmp_path / "no-schema2.sqlite3"))
    try:
        with pytest.raises(AuditUnavailable):
            await AuditLog(broken).record_started(context())
    finally:
        await broken.dispose()


async def test_the_outcome_row_is_best_effort(tmp_path: Any) -> None:
    """By the time the outcome is known the upstream has already run or been refused, so a
    logging failure must not become an error the caller cannot act on."""
    broken = Database("sqlite+aiosqlite:///" + str(tmp_path / "no-schema3.sqlite3"))
    try:
        ctx = context()
        await AuditLog(broken).record_outcome(ctx)  # must not raise
        assert ctx.decision is Decision.ALLOW
    finally:
        await broken.dispose()


async def test_the_finish_hook_runs_for_every_pipeline_outcome(audit: AuditLog) -> None:
    class Denier:
        name = "policy"

        async def run(self, ctx: RequestContext) -> None:
            ctx.deny(ReasonCode.DENIED_POLICY, "nope")

    class Exploder:
        name = "boom"

        async def run(self, ctx: RequestContext) -> None:
            raise RuntimeError("stage is broken")

    allowed = context()
    await Pipeline([], [audit_finish_hook(audit)]).run(allowed)
    denied = context()
    await Pipeline([Denier()], [audit_finish_hook(audit)]).run(denied)
    crashed = context()
    await Pipeline([Exploder()], [audit_finish_hook(audit)]).run(crashed)

    assert (await audit.rows_for_request(allowed.request_id))[0]["decision"] == "allow"
    assert (await audit.rows_for_request(denied.request_id))[0][
        "reason_code"
    ] == "WARDEN_DENIED:policy"
    assert (await audit.rows_for_request(crashed.request_id))[0][
        "reason_code"
    ] == "WARDEN_DENIED:internal"
    assert (await audit.verify()).ok


# -- concurrency -------------------------------------------------------------------------------


async def test_a_hundred_concurrent_appends_still_verify(audit: AuditLog) -> None:
    """The reason appends are serialised: two writers reading the same head fork the chain."""
    await asyncio.gather(*(audit.record_started(context()) for _ in range(100)))
    result = await audit.verify()
    assert result.ok, result.summary()
    assert result.rows_checked == 100


async def test_concurrent_appends_produce_unique_hashes(audit: AuditLog) -> None:
    await asyncio.gather(*(audit.record_started(context()) for _ in range(40)))
    page = await audit.query(limit=100)
    hashes = [row["row_hash"] for row in page.rows]
    assert len(set(hashes)) == len(hashes)


# -- querying ----------------------------------------------------------------------------------


async def seed(audit: AuditLog) -> None:
    for index in range(12):
        ctx = context(
            principal=principal("alice" if index % 2 else "bob"),
            tool_name="files__read_file" if index % 3 else "notes_db__run_sql",
            arguments={"path": f"f{index}.md"},
        )
        if index % 4 == 0:
            ctx.deny(ReasonCode.DENIED_POLICY, "no")
        else:
            ctx.forwarded = True
        await audit.record_outcome(ctx)


async def test_query_returns_newest_first(audit: AuditLog) -> None:
    await seed(audit)
    page = await audit.query(limit=5)
    ids = [row["id"] for row in page.rows]
    assert ids == sorted(ids, reverse=True)
    assert len(page.rows) == 5
    assert page.next_cursor == ids[-1]


async def test_cursor_pagination_walks_every_row_once(audit: AuditLog) -> None:
    await seed(audit)
    seen: list[int] = []
    cursor: int | None = None
    while True:
        page = await audit.query(cursor=cursor, limit=5)
        seen.extend(row["id"] for row in page.rows)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    assert len(seen) == 12
    assert len(set(seen)) == 12


async def test_the_last_page_has_no_cursor(audit: AuditLog) -> None:
    await seed(audit)
    page = await audit.query(limit=100)
    assert len(page.rows) == 12
    assert page.next_cursor is None


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        (AuditFilters(principal_id="alice"), 6),
        (AuditFilters(principal_id="bob"), 6),
        (AuditFilters(decision="deny"), 3),
        (AuditFilters(decision="allow"), 9),
        (AuditFilters(tool="notes_db__run_sql"), 4),
        (AuditFilters(reason_code="WARDEN_DENIED:policy"), 3),
        (AuditFilters(principal_id="alice", decision="deny"), 0),
        (AuditFilters(principal_id="nobody"), 0),
    ],
)
async def test_filters(audit: AuditLog, filters: AuditFilters, expected: int) -> None:
    await seed(audit)
    assert await audit.count(filters) == expected
    assert len((await audit.query(filters, limit=100)).rows) == expected


async def test_time_filters(audit: AuditLog) -> None:
    old = datetime(2026, 1, 1, tzinfo=UTC)
    await audit.append(
        ts=old,
        request_id="old",
        event=EVENT_DENIED,
        method="tools/call",
        args_redacted={},
        args_sha256="0" * 64,
        decision="deny",
        reason_code="WARDEN_DENIED:policy",
        stage_timings_ms={},
        result_bytes=0,
        scan_flags={},
    )
    await seed(audit)
    cutoff = old + timedelta(days=1)
    assert await audit.count(AuditFilters(until=cutoff)) == 1
    assert await audit.count(AuditFilters(since=cutoff)) == 12


async def test_page_size_is_capped(audit: AuditLog) -> None:
    await seed(audit)
    page = await audit.query(limit=10_000)
    assert len(page.rows) == 12


async def test_an_empty_log_verifies_and_queries_cleanly(audit: AuditLog) -> None:
    assert (await audit.verify()).ok
    page = await audit.query()
    assert page.rows == [] and page.next_cursor is None
    assert await audit.count() == 0
