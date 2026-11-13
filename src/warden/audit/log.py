"""Appending to, and reading back, the audit log.

Appending is serialised: the writer reads the current head, computes the next hash from it and
inserts, all inside one transaction holding a lock. Without that, two concurrent requests both
read the same head and the chain forks - which `verify` would report as tampering, from an
honest gateway under load.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from sqlalchemy import select

from warden.audit.chain import (
    GENESIS_HASH,
    VerifyResult,
    compute_row_hash,
    hash_arguments,
    verify_rows,
)
from warden.db.base import utcnow
from warden.db.engine import AUDIT_CHAIN_LOCK_KEY, Database
from warden.db.models import AuditEvent
from warden.errors import ReasonCode
from warden.logging import REDACTED, get_logger, redact
from warden.pipeline import Decision, RequestContext

logger = get_logger(__name__)

EVENT_STARTED: Final = "started"
EVENT_FINISHED: Final = "finished"
EVENT_DENIED: Final = "denied"

#: How many rows `verify` reads at a time, so a long chain does not have to fit in memory.
VERIFY_PAGE_SIZE: Final = 2000
DEFAULT_PAGE_SIZE: Final = 100
MAX_PAGE_SIZE: Final = 1000


class AuditUnavailable(RuntimeError):
    """The audit log could not be written, so the call must not proceed."""


@dataclass(slots=True)
class AuditFilters:
    """What `/admin/audit` and `warden audit tail` can narrow by."""

    principal_id: str | None = None
    tool: str | None = None
    decision: str | None = None
    event: str | None = None
    reason_code: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    request_id: str | None = None


@dataclass(slots=True)
class AuditPage:
    """One page of rows, plus the cursor that fetches the next."""

    rows: list[dict[str, Any]] = field(default_factory=list)
    next_cursor: int | None = None


class AuditLog:
    """The only thing that writes `audit_events`."""

    def __init__(self, database: Database) -> None:
        self._db = database
        # Serialises appends inside this process. On Postgres the advisory lock also serialises
        # across processes; SQLite is single-node by definition, so this is the whole story
        # there.
        self._append_lock = asyncio.Lock()

    # -- writing -------------------------------------------------------------------------

    async def append(self, **fields: Any) -> AuditEvent:
        """Append one row, chaining it to the current head. Raises on any failure."""
        async with (
            self._append_lock,
            self._db.transaction_with_lock(AUDIT_CHAIN_LOCK_KEY) as session,
        ):
            head = (
                await session.execute(
                    select(AuditEvent.row_hash).order_by(AuditEvent.id.desc()).limit(1)
                )
            ).scalar_one_or_none()
            row = AuditEvent(
                ts=fields.pop("ts", None) or utcnow(),
                prev_hash=head or GENESIS_HASH,
                **fields,
            )
            row.row_hash = compute_row_hash(row)
            session.add(row)
            await session.flush()
            return row

    async def record_started(self, ctx: RequestContext) -> AuditEvent:
        """Write the write-ahead row. The caller must treat a failure as a denial.

        This runs *before* the upstream is reached, so a call that cannot be recorded is a call
        that does not happen. That is the whole point of hard rule 1 for the audit log: a
        gateway whose log is down must stop acting, not keep acting unobserved.
        """
        try:
            return await self.append(**_row_fields(ctx, EVENT_STARTED))
        except Exception as exc:
            logger.error(
                "audit write-ahead failed; the call will be denied",
                extra={
                    "warden": {
                        "request_id": ctx.request_id,
                        "tool": ctx.tool_name,
                        "error": f"{type(exc).__name__}: {exc}"[:300],
                    }
                },
            )
            raise AuditUnavailable(str(exc)) from exc

    async def record_approval_event(self, event: str, approval: dict[str, Any]) -> None:
        """Append a row for an approval lifecycle moment.

        Approvals are the one security decision a *human* makes, so they belong in the same
        hash-chained log as everything else: a reviewer asking "who let this through?" should
        not have to join two tables, and an approval trail that is not tamper-evident is not
        much of a trail.
        """
        try:
            await self.append(
                request_id=str(approval.get("request_id") or approval.get("id") or ""),
                event=event,
                principal_id=approval.get("decided_by") or approval.get("principal_id"),
                auth_method="approval",
                method="approvals/decide",
                tool=approval.get("tool"),
                upstream=None,
                risk=approval.get("risk"),
                # Already redacted when the approval was created.
                args_redacted=dict(approval.get("args_redacted") or {}),
                args_sha256=str(approval.get("args_sha256") or ""),
                decision=str(approval.get("status") or ""),
                reason_code=event,
                matched_rule=None,
                stage_timings_ms={},
                result_bytes=0,
                scan_flags={
                    "approval": {
                        "id": approval.get("id"),
                        "requested_by": approval.get("principal_id"),
                        "decided_by": approval.get("decided_by"),
                        "reason": approval.get("decision_reason"),
                    }
                },
            )
        except Exception as exc:
            logger.error(
                "approval event could not be recorded",
                extra={
                    "warden": {
                        "event": event,
                        "approval_id": approval.get("id"),
                        "error": f"{type(exc).__name__}: {exc}"[:200],
                    }
                },
            )

    async def record_outcome(self, ctx: RequestContext) -> None:
        """Write the closing row, best effort.

        Best effort because by now the upstream has either run or been refused: failing the
        request would change nothing that already happened, and would turn a logging outage
        into an error the caller cannot act on. The failure is logged at ERROR, and a `started`
        row with no `finished` row is itself the evidence that something went wrong.
        """
        event = EVENT_FINISHED if ctx.forwarded else EVENT_DENIED
        try:
            await self.append(**_row_fields(ctx, event))
        except Exception as exc:
            logger.error(
                "audit outcome row could not be written",
                extra={
                    "warden": {
                        "request_id": ctx.request_id,
                        "event": event,
                        "tool": ctx.tool_name,
                        "decision": str(ctx.decision),
                        "reason_code": str(ctx.reason_code),
                        "error": f"{type(exc).__name__}: {exc}"[:300],
                    }
                },
            )

    # -- reading -------------------------------------------------------------------------

    async def query(
        self,
        filters: AuditFilters | None = None,
        *,
        cursor: int | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
    ) -> AuditPage:
        """A page of rows, newest first, with a cursor for the next page.

        The cursor is the last id seen, not an offset: an offset shifts under you as rows are
        appended, which on an append-only table happens constantly.
        """
        page_size = max(1, min(limit, MAX_PAGE_SIZE))
        statement = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(page_size + 1)
        statement = _apply_filters(statement, filters or AuditFilters())
        if cursor is not None:
            statement = statement.where(AuditEvent.id < cursor)
        async with self._db.session() as session:
            rows = list((await session.execute(statement)).scalars())
        has_more = len(rows) > page_size
        visible = rows[:page_size]
        return AuditPage(
            rows=[row.as_dict() for row in visible],
            next_cursor=visible[-1].id if has_more and visible else None,
        )

    async def count(self, filters: AuditFilters | None = None) -> int:
        from sqlalchemy import func

        statement = select(func.count()).select_from(AuditEvent)
        statement = _apply_filters(statement, filters or AuditFilters())
        async with self._db.session() as session:
            return int((await session.execute(statement)).scalar_one())

    async def rows_for_request(self, request_id: str) -> list[dict[str, Any]]:
        async with self._db.session() as session:
            rows = list(
                (
                    await session.execute(
                        select(AuditEvent)
                        .where(AuditEvent.request_id == request_id)
                        .order_by(AuditEvent.id)
                    )
                ).scalars()
            )
        return [row.as_dict() for row in rows]

    # -- verifying -----------------------------------------------------------------------

    async def verify(self) -> VerifyResult:
        """Walk the whole chain in id order, a page at a time."""
        checked = 0
        head = GENESIS_HASH
        last_id = 0
        while True:
            async with self._db.session() as session:
                rows = list(
                    (
                        await session.execute(
                            select(AuditEvent)
                            .where(AuditEvent.id > last_id)
                            .order_by(AuditEvent.id)
                            .limit(VERIFY_PAGE_SIZE)
                        )
                    ).scalars()
                )
            if not rows:
                return VerifyResult(ok=True, rows_checked=checked, head_hash=head)
            result = verify_rows(rows, head)
            checked += result.rows_checked
            if not result.ok:
                return VerifyResult(
                    ok=False,
                    rows_checked=checked,
                    first_break=result.first_break,
                    head_hash=result.head_hash,
                )
            head = result.head_hash
            last_id = int(rows[-1].id)


def _apply_filters(statement: Any, filters: AuditFilters) -> Any:
    if filters.principal_id:
        statement = statement.where(AuditEvent.principal_id == filters.principal_id)
    if filters.tool:
        statement = statement.where(AuditEvent.tool == filters.tool)
    if filters.decision:
        statement = statement.where(AuditEvent.decision == filters.decision)
    if filters.event:
        statement = statement.where(AuditEvent.event == filters.event)
    if filters.reason_code:
        statement = statement.where(AuditEvent.reason_code == filters.reason_code)
    if filters.request_id:
        statement = statement.where(AuditEvent.request_id == filters.request_id)
    if filters.since:
        statement = statement.where(AuditEvent.ts >= filters.since)
    if filters.until:
        statement = statement.where(AuditEvent.ts <= filters.until)
    return statement


def mask_paths(value: Any, paths: Iterable[str]) -> Any:
    """Replace the values at `paths` with the redaction marker.

    `redact()` masks by key *name*, which cannot see a credential sent under an innocent key.
    The DLP scanner knows exactly where it found one, so those paths are masked by position.
    """
    wanted = {path for path in paths if path and path != "<root>"}
    if not wanted:
        return value
    return _mask(value, "", wanted)


def _mask(value: Any, path: str, wanted: set[str]) -> Any:
    if path in wanted:
        return REDACTED
    if isinstance(value, dict):
        return {
            key: _mask(item, f"{path}.{key}" if path else str(key), wanted)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_mask(item, f"{path}[{index}]", wanted) for index, item in enumerate(value)]
    return value


def _row_fields(ctx: RequestContext, event: str) -> dict[str, Any]:
    """Turn a request context into the row to append.

    Hard rule 2 lives here: `args_redacted` goes through `redact`, and the only complete record
    of the arguments is their hash.
    """
    result_hash: str | None = None
    if ctx.result is not None:
        from warden.audit.chain import canonical_json, sha256_text

        with contextlib.suppress(Exception):
            result_hash = sha256_text(canonical_json(ctx.result.model_dump(mode="json")))
    return {
        "request_id": ctx.request_id,
        "event": event,
        "principal_id": ctx.principal.user_id if ctx.principal else None,
        "auth_method": ctx.principal.auth_method if ctx.principal else None,
        "method": ctx.method,
        "tool": ctx.tool_name,
        "upstream": ctx.upstream,
        "risk": str(ctx.risk),
        "args_redacted": mask_paths(redact(ctx.arguments), ctx.redact_paths),
        "args_sha256": hash_arguments(ctx.arguments),
        "decision": str(ctx.decision) if event != EVENT_STARTED else str(Decision.ALLOW),
        "reason_code": str(ctx.reason_code) if event != EVENT_STARTED else str(ReasonCode.ALLOWED),
        "matched_rule": ctx.matched_rule,
        "stage_timings_ms": {name: round(value, 3) for name, value in ctx.stage_timings_ms.items()},
        "result_bytes": ctx.result_bytes,
        "result_sha256": result_hash,
        "scan_flags": dict(ctx.scan_flags),
    }


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "EVENT_DENIED",
    "EVENT_FINISHED",
    "EVENT_STARTED",
    "MAX_PAGE_SIZE",
    "AuditFilters",
    "AuditLog",
    "AuditPage",
    "AuditUnavailable",
]
