"""The approval store: binding, single use, expiry, and concurrent decisions."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from warden.approval.store import (
    ApprovalStatus,
    ApprovalStore,
    ConsumeOutcome,
)
from warden.db.engine import Database

pytestmark = pytest.mark.unit

ARGS = {"path": "notes/a.md"}
DIGEST = "a" * 64


@pytest.fixture
def store(database: Database) -> ApprovalStore:
    return ApprovalStore(database, expiry_seconds=300.0)


async def make(
    store: ApprovalStore,
    *,
    principal: str = "editor-user",
    tool: str = "files__delete_file",
    digest: str = DIGEST,
) -> str:
    request = await store.create(
        principal_id=principal,
        tool=tool,
        args_redacted=ARGS,
        args_sha256=digest,
        request_id="req-1",
        risk="destructive",
    )
    return request.id


# -- creating ----------------------------------------------------------------------------------


async def test_a_new_approval_is_pending_and_expires(store: ApprovalStore) -> None:
    approval_id = await make(store)
    row = await store.get(approval_id)
    assert row is not None
    assert row["status"] == "pending"
    assert row["principal_id"] == "editor-user"
    assert row["tool"] == "files__delete_file"
    assert row["args_sha256"] == DIGEST
    expires = datetime.fromisoformat(row["expires_at"])
    assert expires > datetime.now(UTC)
    assert expires < datetime.now(UTC) + timedelta(seconds=301)


async def test_pending_lists_oldest_first(store: ApprovalStore) -> None:
    first = await make(store, tool="files__delete_file")
    second = await make(store, tool="notes_db__delete_note")
    queue = await store.pending()
    assert [row["id"] for row in queue] == [first, second]


async def test_approval_ids_are_unguessable(store: ApprovalStore) -> None:
    ids = {await make(store, digest=f"{index:064d}") for index in range(20)}
    assert len(ids) == 20
    assert all(len(value) == 24 for value in ids)


# -- deciding ----------------------------------------------------------------------------------


async def test_approving_then_consuming(store: ApprovalStore) -> None:
    approval_id = await make(store)
    changed, message = await store.decide(approval_id, approve=True, decided_by="admin-user")
    assert changed and message == "approved"

    outcome, used = await store.consume(
        principal_id="editor-user", tool="files__delete_file", args_sha256=DIGEST
    )
    assert outcome is ConsumeOutcome.CONSUMED
    assert used == approval_id
    row = await store.get(approval_id)
    assert row is not None and row["status"] == "consumed"
    assert row["consumed_at"] is not None


async def test_an_approval_is_single_use(store: ApprovalStore) -> None:
    approval_id = await make(store)
    await store.decide(approval_id, approve=True, decided_by="admin-user")
    first, _ = await store.consume(
        principal_id="editor-user", tool="files__delete_file", args_sha256=DIGEST
    )
    second, _ = await store.consume(
        principal_id="editor-user", tool="files__delete_file", args_sha256=DIGEST
    )
    assert first is ConsumeOutcome.CONSUMED
    assert second is ConsumeOutcome.ALREADY_USED


async def test_denying_is_reported_on_consume(store: ApprovalStore) -> None:
    approval_id = await make(store)
    changed, _ = await store.decide(
        approval_id, approve=False, decided_by="admin-user", reason="too risky"
    )
    assert changed
    outcome, _ = await store.consume(
        principal_id="editor-user", tool="files__delete_file", args_sha256=DIGEST
    )
    assert outcome is ConsumeOutcome.DENIED
    row = await store.get(approval_id)
    assert row is not None
    assert row["status"] == "denied"
    assert row["decision_reason"] == "too risky"
    assert row["decided_by"] == "admin-user"


async def test_deciding_twice_changes_nothing(store: ApprovalStore) -> None:
    approval_id = await make(store)
    assert (await store.decide(approval_id, approve=True, decided_by="admin-user"))[0]
    changed, message = await store.decide(approval_id, approve=False, decided_by="other-admin")
    assert not changed
    assert "already approved" in message


async def test_deciding_an_unknown_approval(store: ApprovalStore) -> None:
    changed, message = await store.decide("nope", approve=True, decided_by="admin-user")
    assert not changed and message == "no such approval"


# -- separation of duties ----------------------------------------------------------------------


async def test_a_caller_cannot_approve_their_own_request(store: ApprovalStore) -> None:
    """Otherwise "needs approval" means "needs a second click from the same person"."""
    approval_id = await make(store, principal="editor-user")
    changed, message = await store.decide(approval_id, approve=True, decided_by="editor-user")
    assert not changed
    assert "may not approve their own" in message
    row = await store.get(approval_id)
    assert row is not None and row["status"] == "pending"


async def test_self_approval_can_be_relaxed_for_development(database: Database) -> None:
    relaxed = ApprovalStore(database, allow_self_approval=True)
    approval_id = await make(relaxed, principal="editor-user")
    changed, _ = await relaxed.decide(approval_id, approve=True, decided_by="editor-user")
    assert changed


async def test_another_admin_can_still_approve(store: ApprovalStore) -> None:
    approval_id = await make(store, principal="editor-user")
    changed, _ = await store.decide(approval_id, approve=True, decided_by="admin-user")
    assert changed


# -- the binding -------------------------------------------------------------------------------


async def test_an_approval_does_not_work_for_a_different_principal(
    store: ApprovalStore,
) -> None:
    approval_id = await make(store, principal="editor-user")
    await store.decide(approval_id, approve=True, decided_by="admin-user")
    outcome, _ = await store.consume(
        principal_id="someone-else", tool="files__delete_file", args_sha256=DIGEST
    )
    assert outcome is ConsumeOutcome.NOT_FOUND


async def test_an_approval_does_not_work_for_a_different_tool(store: ApprovalStore) -> None:
    approval_id = await make(store, tool="files__delete_file")
    await store.decide(approval_id, approve=True, decided_by="admin-user")
    outcome, _ = await store.consume(
        principal_id="editor-user", tool="notes_db__delete_note", args_sha256=DIGEST
    )
    assert outcome is ConsumeOutcome.NOT_FOUND


async def test_an_approval_does_not_work_for_different_arguments(
    store: ApprovalStore,
) -> None:
    """The replay attack: approve a harmless delete, then swap the path."""
    approval_id = await make(store, digest="a" * 64)
    await store.decide(approval_id, approve=True, decided_by="admin-user")
    outcome, _ = await store.consume(
        principal_id="editor-user", tool="files__delete_file", args_sha256="b" * 64
    )
    assert outcome is ConsumeOutcome.NOT_FOUND
    # ...and the original approval is untouched, so it can still be used for what it approved.
    again, _ = await store.consume(
        principal_id="editor-user", tool="files__delete_file", args_sha256="a" * 64
    )
    assert again is ConsumeOutcome.CONSUMED


async def test_consuming_with_no_approval_at_all(store: ApprovalStore) -> None:
    outcome, approval_id = await store.consume(
        principal_id="nobody", tool="files__delete_file", args_sha256=DIGEST
    )
    assert outcome is ConsumeOutcome.NOT_FOUND
    assert approval_id is None


async def test_consuming_a_pending_approval_reports_still_pending(
    store: ApprovalStore,
) -> None:
    approval_id = await make(store)
    outcome, found = await store.consume(
        principal_id="editor-user", tool="files__delete_file", args_sha256=DIGEST
    )
    assert outcome is ConsumeOutcome.STILL_PENDING
    assert found == approval_id


# -- expiry ------------------------------------------------------------------------------------


async def test_an_expired_approval_cannot_be_decided(database: Database) -> None:
    store = ApprovalStore(database, expiry_seconds=-1.0)
    approval_id = await make(store)
    changed, message = await store.decide(approval_id, approve=True, decided_by="admin-user")
    assert not changed and message == "expired"


async def test_an_expired_pending_approval_is_marked_expired(database: Database) -> None:
    store = ApprovalStore(database, expiry_seconds=-1.0)
    approval_id = await make(store)
    assert await store.status_of(approval_id) is ApprovalStatus.EXPIRED
    row = await store.get(approval_id)
    assert row is not None and row["status"] == "expired"


async def test_an_expired_approval_cannot_be_consumed(database: Database) -> None:
    store = ApprovalStore(database, expiry_seconds=-1.0)
    await make(store)
    outcome, _ = await store.consume(
        principal_id="editor-user", tool="files__delete_file", args_sha256=DIGEST
    )
    assert outcome is ConsumeOutcome.EXPIRED


async def test_expire_due_sweeps_the_queue(database: Database) -> None:
    store = ApprovalStore(database, expiry_seconds=-1.0)
    ids = [await make(store, digest=f"{index:064d}") for index in range(3)]
    expired = await store.expire_due()
    assert set(expired) == set(ids)
    assert await store.pending() == []


async def test_expiry_does_not_touch_a_decided_approval(store: ApprovalStore) -> None:
    approval_id = await make(store)
    await store.decide(approval_id, approve=True, decided_by="admin-user")
    assert await store.expire_due() == []
    assert await store.status_of(approval_id) is ApprovalStatus.APPROVED


async def test_an_approval_expiring_after_being_approved_cannot_be_used(
    database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Approved but left unused past its expiry is not a usable approval."""
    store = ApprovalStore(database, expiry_seconds=0.4)
    approval_id = await make(store)
    assert (await store.decide(approval_id, approve=True, decided_by="admin-user"))[0]
    await asyncio.sleep(0.6)
    outcome, _ = await store.consume(
        principal_id="editor-user", tool="files__delete_file", args_sha256=DIGEST
    )
    assert outcome is ConsumeOutcome.EXPIRED


# -- waiting -----------------------------------------------------------------------------------


async def test_waiting_returns_as_soon_as_a_decision_lands(store: ApprovalStore) -> None:
    approval_id = await make(store)

    async def decide_soon() -> None:
        await asyncio.sleep(0.1)
        await store.decide(approval_id, approve=True, decided_by="admin-user")

    task = asyncio.create_task(decide_soon())
    status = await store.wait_for_decision(approval_id, timeout=5.0)
    await task
    assert status is ApprovalStatus.APPROVED


async def test_waiting_times_out_as_pending_not_denied(store: ApprovalStore) -> None:
    """Nobody said no, so the caller is told to come back - not refused."""
    approval_id = await make(store)
    status = await store.wait_for_decision(approval_id, timeout=0.3)
    assert status is ApprovalStatus.PENDING


async def test_waiting_reports_progress(store: ApprovalStore) -> None:
    approval_id = await make(store)
    ticks: list[tuple[int, float]] = []

    async def on_tick(count: int, remaining: float) -> None:
        ticks.append((count, remaining))

    await store.wait_for_decision(approval_id, timeout=0.7, on_tick=on_tick)
    assert len(ticks) >= 2
    assert ticks[0][0] == 1
    assert ticks[-1][1] < ticks[0][1], "the remaining time must count down"


async def test_waiting_on_a_denied_approval_returns_at_once(store: ApprovalStore) -> None:
    approval_id = await make(store)
    await store.decide(approval_id, approve=False, decided_by="admin-user")
    assert await store.wait_for_decision(approval_id, timeout=5.0) is ApprovalStatus.DENIED


async def test_a_pubsub_notifier_wakes_the_waiter(store: ApprovalStore, database: Database) -> None:
    """With Redis the waiter does not have to poll; without it, it does, and both work."""
    import fakeredis.aioredis

    redis = fakeredis.aioredis.FakeRedis()
    notified = ApprovalStore(database, notifier=redis)
    approval_id = await make(notified)

    async def decide_soon() -> None:
        await asyncio.sleep(0.05)
        await notified.decide(approval_id, approve=True, decided_by="admin-user")

    task = asyncio.create_task(decide_soon())
    status = await notified.wait_for_decision(approval_id, timeout=5.0)
    await task
    assert status is ApprovalStatus.APPROVED


async def test_a_broken_notifier_falls_back_to_polling(database: Database) -> None:
    class BrokenRedis:
        async def publish(self, channel: str, message: str) -> Any:
            raise ConnectionError("redis is down")

        def pubsub(self) -> Any:
            raise ConnectionError("redis is down")

    store = ApprovalStore(database, notifier=BrokenRedis())
    approval_id = await make(store)
    changed, _ = await store.decide(approval_id, approve=True, decided_by="admin-user")
    assert changed, "a publish failure must not fail the decision"
    assert await store.wait_for_decision(approval_id, timeout=2.0) is ApprovalStatus.APPROVED


# -- concurrency -------------------------------------------------------------------------------


async def test_two_approvers_at_once_produce_one_decision(store: ApprovalStore) -> None:
    approval_id = await make(store)
    results = await asyncio.gather(
        store.decide(approval_id, approve=True, decided_by="admin-one"),
        store.decide(approval_id, approve=False, decided_by="admin-two"),
    )
    changed = [outcome for outcome, _ in results if outcome]
    assert len(changed) == 1, f"exactly one decision should stick: {results}"
    row = await store.get(approval_id)
    assert row is not None
    assert row["status"] in ("approved", "denied")
    assert row["decided_by"] in ("admin-one", "admin-two")


async def test_two_retries_at_once_consume_one_approval(store: ApprovalStore) -> None:
    """Single use under concurrency: the whole point of a conditional update."""
    approval_id = await make(store)
    await store.decide(approval_id, approve=True, decided_by="admin-user")
    results = await asyncio.gather(
        *(
            store.consume(principal_id="editor-user", tool="files__delete_file", args_sha256=DIGEST)
            for _ in range(8)
        )
    )
    consumed = [outcome for outcome, _ in results if outcome is ConsumeOutcome.CONSUMED]
    assert len(consumed) == 1, f"only one consume should win: {results}"


async def test_recent_shows_decided_approvals(store: ApprovalStore) -> None:
    approved = await make(store, digest="a" * 64)
    denied = await make(store, digest="b" * 64)
    await store.decide(approved, approve=True, decided_by="admin-user")
    await store.decide(denied, approve=False, decided_by="admin-user")
    rows = await store.recent()
    statuses = {row["id"]: row["status"] for row in rows}
    assert statuses[approved] == "approved"
    assert statuses[denied] == "denied"
