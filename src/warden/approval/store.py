"""Creating, deciding and consuming approvals.

An approval is bound to the triple **(principal, tool, argument hash)** and is **single-use**.
Those two properties are what make it un-replayable:

* it cannot be carried to another caller, another tool, or the same tool with different
  arguments, because the binding is checked on use and not merely on creation;
* it cannot be used twice, because consuming it is a conditional update that only one caller
  can win.

Both the "approve" and the "consume" steps are compare-and-set updates rather than
read-then-write, so two approvers clicking at once produce one decision, and two retries of the
same call produce one forwarded call.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final, Protocol

from sqlalchemy import select, update

from warden.db.engine import Database
from warden.db.models import Approval
from warden.logging import get_logger

logger = get_logger(__name__)

#: Redis channel decisions are published on, so a gateway waiting on an approval wakes
#: immediately rather than at the end of its poll interval - and so it works when the decision
#: is made by a *different* gateway process.
DECISION_CHANNEL: Final = "warden:approvals:decided"
#: How often a waiter re-reads the row when pub/sub is unavailable. Low enough to feel instant,
#: high enough not to hammer the database.
POLL_INTERVAL_SECONDS: Final = 0.25


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class ConsumeOutcome(StrEnum):
    """What happened when a caller tried to use an approval."""

    CONSUMED = "consumed"
    NOT_FOUND = "not_found"
    STILL_PENDING = "still_pending"
    DENIED = "denied"
    EXPIRED = "expired"
    ALREADY_USED = "already_used"


class Notifier(Protocol):
    """The slice of Redis pub/sub the waiter needs."""

    async def publish(self, channel: str, message: str) -> Any: ...
    def pubsub(self) -> Any: ...


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """A pending approval, as handed back to the stage that created it."""

    id: str
    expires_at: datetime
    status: ApprovalStatus

    @property
    def pending(self) -> bool:
        return self.status is ApprovalStatus.PENDING


async def _affected_rows(session: Any, statement: Any) -> int:
    """How many rows a conditional UPDATE changed.

    Wrapped because `rowcount` is on the DBAPI cursor rather than the typed `Result`, and
    because the number is the whole point: a compare-and-set that changed zero rows means
    somebody else got there first, which is how two approvers clicking at once produce one
    decision.
    """
    result = await session.execute(statement)
    return int(getattr(result, "rowcount", 0) or 0)


class ApprovalStore:
    """The only thing that writes `approvals`."""

    def __init__(
        self,
        database: Database,
        *,
        notifier: Notifier | None = None,
        expiry_seconds: float = 300.0,
        allow_self_approval: bool = False,
        on_event: Any | None = None,
    ) -> None:
        self._db = database
        self._notifier = notifier
        self._expiry_seconds = expiry_seconds
        self.allow_self_approval = allow_self_approval
        #: `await on_event(event, approval_row)` for every create, decision, consume and
        #: expiry. The app wires this to the audit log, so the approval trail lands in the same
        #: hash-chained place as everything else rather than in a table nobody verifies.
        self._on_event = on_event

    async def _emit(self, event: str, approval_id: str) -> None:
        if self._on_event is None:
            return
        try:
            row = await self.get(approval_id)
            if row is not None:
                outcome = self._on_event(event, row)
                if asyncio.iscoroutine(outcome):
                    await outcome
        except Exception:
            logger.exception("could not record an approval event")

    # -- creating ------------------------------------------------------------------------

    async def create(
        self,
        *,
        principal_id: str,
        tool: str,
        args_redacted: dict[str, Any],
        args_sha256: str,
        request_id: str,
        risk: str | None = None,
        scan_flags: dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        """Record a pending approval and return its id."""
        approval_id = secrets.token_hex(12)
        expires_at = datetime.now(UTC) + timedelta(seconds=self._expiry_seconds)
        async with self._db.session() as session:
            session.add(
                Approval(
                    id=approval_id,
                    principal_id=principal_id,
                    tool=tool,
                    args_redacted=args_redacted,
                    args_sha256=args_sha256,
                    risk=risk,
                    scan_flags=scan_flags or {},
                    status=str(ApprovalStatus.PENDING),
                    request_id=request_id,
                    expires_at=expires_at,
                )
            )
        logger.warning(
            "approval requested",
            extra={
                "warden": {
                    "approval_id": approval_id,
                    "principal": principal_id,
                    "tool": tool,
                    "args_sha256": args_sha256,
                    "expires_at": expires_at.isoformat(),
                }
            },
        )
        await self._emit("approval_requested", approval_id)
        return ApprovalRequest(id=approval_id, expires_at=expires_at, status=ApprovalStatus.PENDING)

    # -- deciding ------------------------------------------------------------------------

    async def decide(
        self,
        approval_id: str,
        *,
        approve: bool,
        decided_by: str,
        reason: str | None = None,
    ) -> tuple[bool, str]:
        """Approve or deny. Returns (changed, message).

        A conditional UPDATE, not a read-then-write: two approvers clicking at the same instant
        produce exactly one decision, and the loser is told so rather than silently overwriting.
        """
        now = datetime.now(UTC)
        new_status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED

        async with self._db.session() as session:
            row = (
                await session.execute(select(Approval).where(Approval.id == approval_id))
            ).scalar_one_or_none()
            if row is None:
                return False, "no such approval"
            if row.status != str(ApprovalStatus.PENDING):
                return False, f"already {row.status}"
            if row.expires_at <= now:
                return False, "expired"
            if not self.allow_self_approval and row.principal_id == decided_by:
                # Separation of duties. Without this, "needs approval" means "needs a second
                # click from the same person", which is not a control.
                logger.warning(
                    "self-approval refused",
                    extra={
                        "warden": {
                            "approval_id": approval_id,
                            "principal": decided_by,
                            "tool": row.tool,
                        }
                    },
                )
                return False, "a caller may not approve their own request"

            if (
                await _affected_rows(
                    session,
                    update(Approval)
                    .where(
                        Approval.id == approval_id,
                        Approval.status == str(ApprovalStatus.PENDING),
                    )
                    .values(
                        status=str(new_status),
                        decided_by=decided_by,
                        decided_at=now,
                        decision_reason=reason,
                    ),
                )
                == 0
            ):
                return False, "another approver decided first"

        logger.warning(
            "approval decided",
            extra={
                "warden": {
                    "approval_id": approval_id,
                    "status": str(new_status),
                    "decided_by": decided_by,
                }
            },
        )
        await self._emit(f"approval_{new_status}", approval_id)
        await self._publish(approval_id)
        return True, str(new_status)

    async def _publish(self, approval_id: str) -> None:
        if self._notifier is None:
            return
        with contextlib.suppress(Exception):
            await self._notifier.publish(DECISION_CHANNEL, approval_id)

    # -- waiting -------------------------------------------------------------------------

    async def wait_for_decision(
        self, approval_id: str, *, timeout: float, on_tick: Any | None = None
    ) -> ApprovalStatus:
        """Block until the approval is decided, expires, or `timeout` elapses.

        Returns the status as it stands when we stop waiting - `PENDING` on timeout, which the
        caller turns into `WARDEN_PENDING:approval` rather than a denial, because nobody has
        said no.
        """
        deadline = asyncio.get_running_loop().time() + timeout
        ticks = 0
        async with self._subscription() as wake:
            while True:
                status = await self.status_of(approval_id)
                if status is not ApprovalStatus.PENDING:
                    return status
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    return ApprovalStatus.PENDING
                ticks += 1
                if on_tick is not None:
                    outcome = on_tick(ticks, remaining)
                    if asyncio.iscoroutine(outcome):
                        await outcome
                await wake(min(POLL_INTERVAL_SECONDS, remaining))

    @contextlib.asynccontextmanager
    async def _subscription(self) -> AsyncIterator[Any]:
        """Yield a `wake(seconds)` coroutine that returns early when a decision is published.

        Pub/sub is an optimisation, not a requirement: without it the waiter polls, which is
        correct but adds up to one poll interval of latency. A subscription that cannot be
        established is logged at debug and the poller takes over.
        """
        pubsub = None
        if self._notifier is not None:
            try:
                pubsub = self._notifier.pubsub()
                await pubsub.subscribe(DECISION_CHANNEL)
            except Exception:
                pubsub = None

        async def wake(seconds: float) -> None:
            if pubsub is None:
                await asyncio.sleep(seconds)
                return
            try:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=seconds)
            except Exception:
                await asyncio.sleep(seconds)
                return
            if message is None:
                return

        try:
            yield wake
        finally:
            if pubsub is not None:
                with contextlib.suppress(Exception):
                    await pubsub.unsubscribe(DECISION_CHANNEL)
                with contextlib.suppress(Exception):
                    await pubsub.aclose()

    async def status_of(self, approval_id: str) -> ApprovalStatus:
        """The current status, expiring the row in passing if its time has come."""
        async with self._db.session() as session:
            row = (
                await session.execute(select(Approval).where(Approval.id == approval_id))
            ).scalar_one_or_none()
            if row is None:
                return ApprovalStatus.EXPIRED
            if row.status == str(ApprovalStatus.PENDING) and row.expires_at <= datetime.now(UTC):
                row.status = str(ApprovalStatus.EXPIRED)
                return ApprovalStatus.EXPIRED
            return ApprovalStatus(row.status)

    # -- consuming -----------------------------------------------------------------------

    async def consume(
        self, *, principal_id: str, tool: str, args_sha256: str
    ) -> tuple[ConsumeOutcome, str | None]:
        """Use an approval for this exact call, exactly once.

        The binding is re-checked here, not trusted from when the row was created: an approval
        is looked up *by* (principal, tool, args hash), so a different caller or different
        arguments simply do not find it. Returns the approval id when one was consumed.
        """
        outcome, approval_id = await self._consume_in_transaction(
            principal_id=principal_id, tool=tool, args_sha256=args_sha256
        )
        if outcome is ConsumeOutcome.CONSUMED and approval_id is not None:
            logger.warning(
                "approval consumed",
                extra={
                    "warden": {
                        "approval_id": approval_id,
                        "principal": principal_id,
                        "tool": tool,
                    }
                },
            )
            # Emitted only once the transaction above has committed: writing an audit row from
            # inside it would deadlock on SQLite, which serialises writers on the file, and
            # would read uncommitted state on Postgres.
            await self._emit("approval_consumed", approval_id)
        return outcome, approval_id

    async def _consume_in_transaction(
        self, *, principal_id: str, tool: str, args_sha256: str
    ) -> tuple[ConsumeOutcome, str | None]:
        """The database half of `consume`: find the approval and claim it, or report why not."""
        now = datetime.now(UTC)
        async with self._db.session() as session:
            candidates = list(
                (
                    await session.execute(
                        select(Approval)
                        .where(
                            Approval.principal_id == principal_id,
                            Approval.tool == tool,
                            Approval.args_sha256 == args_sha256,
                        )
                        .order_by(Approval.created_at.desc())
                    )
                ).scalars()
            )
            if not candidates:
                return ConsumeOutcome.NOT_FOUND, None

            usable = [
                row
                for row in candidates
                if row.status == str(ApprovalStatus.APPROVED) and row.expires_at > now
            ]
            if usable:
                target = usable[0]
                claimed = await _affected_rows(
                    session,
                    update(Approval)
                    .where(
                        Approval.id == target.id,
                        Approval.status == str(ApprovalStatus.APPROVED),
                    )
                    .values(status=str(ApprovalStatus.CONSUMED), consumed_at=now),
                )
                if claimed == 0:
                    # Another retry of the same call claimed it first. Single use holds.
                    return ConsumeOutcome.ALREADY_USED, target.id
                return ConsumeOutcome.CONSUMED, target.id

            newest = candidates[0]
            if newest.status == str(ApprovalStatus.DENIED):
                return ConsumeOutcome.DENIED, newest.id
            if newest.status == str(ApprovalStatus.CONSUMED):
                return ConsumeOutcome.ALREADY_USED, newest.id
            if newest.status == str(ApprovalStatus.PENDING):
                if newest.expires_at <= now:
                    newest.status = str(ApprovalStatus.EXPIRED)
                    return ConsumeOutcome.EXPIRED, newest.id
                return ConsumeOutcome.STILL_PENDING, newest.id
            return ConsumeOutcome.EXPIRED, newest.id

    # -- reading and housekeeping --------------------------------------------------------

    async def pending(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Pending approvals that have not expired, oldest first: the approval queue."""
        await self.expire_due()
        async with self._db.session() as session:
            rows = list(
                (
                    await session.execute(
                        select(Approval)
                        .where(Approval.status == str(ApprovalStatus.PENDING))
                        .order_by(Approval.created_at)
                        .limit(limit)
                    )
                ).scalars()
            )
        return [row.as_dict() for row in rows]

    async def get(self, approval_id: str) -> dict[str, Any] | None:
        async with self._db.session() as session:
            row = (
                await session.execute(select(Approval).where(Approval.id == approval_id))
            ).scalar_one_or_none()
            return row.as_dict() if row is not None else None

    async def recent(self, *, limit: int = 50) -> list[dict[str, Any]]:
        async with self._db.session() as session:
            rows = list(
                (
                    await session.execute(
                        select(Approval).order_by(Approval.created_at.desc()).limit(limit)
                    )
                ).scalars()
            )
        return [row.as_dict() for row in rows]

    async def expire_due(self) -> Sequence[str]:
        """Mark every overdue pending approval expired. Returns the ids that changed."""
        now = datetime.now(UTC)
        async with self._db.session() as session:
            rows = list(
                (
                    await session.execute(
                        select(Approval).where(
                            Approval.status == str(ApprovalStatus.PENDING),
                            Approval.expires_at <= now,
                        )
                    )
                ).scalars()
            )
            for row in rows:
                row.status = str(ApprovalStatus.EXPIRED)
            expired = [row.id for row in rows]
        for approval_id in expired:
            await self._emit("approval_expired", approval_id)
        return expired


__all__ = [
    "DECISION_CHANNEL",
    "POLL_INTERVAL_SECONDS",
    "ApprovalRequest",
    "ApprovalStatus",
    "ApprovalStore",
    "ConsumeOutcome",
    "Notifier",
]
