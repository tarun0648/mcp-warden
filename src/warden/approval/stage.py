"""The Approval pipeline stage.

Runs after DLP and before the audit write-ahead, so a call that is waiting for a human has not
yet been recorded as started - it has not started.

Three outcomes:

* **approved** - an existing approval for this exact (principal, tool, arguments) is consumed
  and the call proceeds. Exactly once: consuming is a conditional update.
* **denied** - `WARDEN_DENIED:approval_denied`.
* **still waiting** - a pending approval is created (or an existing one reused), the stage waits
  up to `wait_seconds` sending progress notifications, and if nobody has decided by then the
  call returns `WARDEN_PENDING:approval` with the approval id. Pending is not a denial: nobody
  said no, and the caller may retry.
"""

from __future__ import annotations

from typing import Any

from warden.approval.store import ApprovalStatus, ApprovalStore, ConsumeOutcome
from warden.audit.chain import hash_arguments
from warden.errors import ReasonCode
from warden.logging import get_logger, redact
from warden.pipeline import RequestContext

logger = get_logger(__name__)


class Approval:
    """Hold a risky call until a human decides."""

    name = "approval"

    def __init__(self, store: ApprovalStore, *, wait_seconds: float = 60.0) -> None:
        self._store = store
        self._wait_seconds = wait_seconds

    async def run(self, ctx: RequestContext) -> None:
        if not ctx.requires_approval:
            return
        if ctx.principal is None or ctx.tool_name is None:  # pragma: no cover
            ctx.deny(ReasonCode.DENIED_AUTH, "the caller is not authenticated")
            return

        digest = hash_arguments(ctx.arguments)
        principal_id = ctx.principal.user_id

        # Already approved from an earlier attempt? Use it, once.
        outcome, approval_id = await self._store.consume(
            principal_id=principal_id, tool=ctx.tool_name, args_sha256=digest
        )
        ctx.approval_id = approval_id
        if outcome is ConsumeOutcome.CONSUMED:
            ctx.scan_flags["approval"] = {"id": approval_id, "status": "consumed"}
            return
        if outcome is ConsumeOutcome.DENIED:
            ctx.deny(
                ReasonCode.DENIED_APPROVAL_DENIED,
                "a human denied this call",
            )
            return
        if outcome is ConsumeOutcome.ALREADY_USED:
            # Single use. A second attempt with the same arguments needs a second approval.
            ctx.deny(
                ReasonCode.DENIED_APPROVAL_DENIED,
                "that approval has already been used; approvals are single-use, so this call "
                "needs a new one",
            )
            return

        if outcome is ConsumeOutcome.STILL_PENDING and approval_id is not None:
            status = await self._wait(ctx, approval_id)
        else:
            request = await self._create(ctx, digest, principal_id)
            if request is None:
                return
            approval_id = request.id
            ctx.approval_id = approval_id
            status = await self._wait(ctx, approval_id)

        if status is ApprovalStatus.APPROVED:
            used, used_id = await self._store.consume(
                principal_id=principal_id, tool=ctx.tool_name, args_sha256=digest
            )
            if used is ConsumeOutcome.CONSUMED:
                ctx.scan_flags["approval"] = {"id": used_id, "status": "consumed"}
                return
            ctx.deny(
                ReasonCode.DENIED_APPROVAL_DENIED,
                "the approval could not be used; it may have been used already or expired",
            )
            return
        if status is ApprovalStatus.DENIED:
            ctx.deny(ReasonCode.DENIED_APPROVAL_DENIED, "a human denied this call")
            return
        if status is ApprovalStatus.EXPIRED:
            ctx.deny(
                ReasonCode.DENIED_APPROVAL_DENIED,
                "the approval request expired before anyone decided",
            )
            return

        ctx.scan_flags["approval"] = {"id": approval_id, "status": "pending"}
        ctx.pend(
            ReasonCode.PENDING_APPROVAL,
            f"this call needs a human to approve it (approval {approval_id}); "
            f"retry the same call with the same arguments once it has been approved",
        )

    async def _create(self, ctx: RequestContext, digest: str, principal_id: str) -> Any | None:
        if ctx.tool_name is None:
            # Unreachable after ResolveTool; raising turns it into WARDEN_DENIED:internal.
            raise RuntimeError("approval stage reached without a resolved tool")
        try:
            return await self._store.create(
                principal_id=principal_id,
                tool=ctx.tool_name,
                args_redacted=redact(ctx.arguments),
                args_sha256=digest,
                request_id=ctx.request_id,
                risk=str(ctx.risk),
                scan_flags=dict(ctx.scan_flags),
            )
        except Exception as exc:
            logger.error(
                "could not record an approval request",
                extra={
                    "warden": {
                        "tool": ctx.tool_name,
                        "error": f"{type(exc).__name__}: {exc}"[:200],
                    }
                },
            )
            # Fail closed: a call that needs a human, and that no human can be asked about,
            # does not happen.
            ctx.deny(
                ReasonCode.DENIED_APPROVAL_UNAVAILABLE,
                "this call needs human approval and the approval store is unavailable",
            )
            return None

    async def _wait(self, ctx: RequestContext, approval_id: str) -> ApprovalStatus:
        """Wait for a decision, reporting progress to a client that asked for it."""

        async def tick(count: int, remaining: float) -> None:
            if ctx.progress is None:
                return
            await ctx.progress(
                count,
                f"waiting for a human to approve {ctx.tool_name} "
                f"({remaining:.0f}s left, approval {approval_id})",
            )

        return await self._store.wait_for_decision(
            approval_id, timeout=self._wait_seconds, on_tick=tick
        )


__all__ = ["Approval"]
