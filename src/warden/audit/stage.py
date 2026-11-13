"""The audit stage and the finish hook.

Two halves, deliberately:

* `AuditWriteAhead` runs immediately before `forward`. If it cannot write, the call is denied
  with `WARDEN_DENIED:audit_unavailable` and the upstream is never reached.
* `audit_finish_hook` runs in the pipeline's `finally`, so it records the outcome of every
  request - allowed, denied, or crashed in a stage.
"""

from __future__ import annotations

from warden.audit.log import AuditLog, AuditUnavailable
from warden.errors import ReasonCode
from warden.logging import get_logger
from warden.pipeline import FinishHook, RequestContext

logger = get_logger(__name__)


class AuditWriteAhead:
    """Record the intent to forward, before forwarding.

    A gateway that cannot write its log must stop acting rather than keep acting unobserved, so
    a failure here is a denial and not a warning.
    """

    name = "audit"

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit

    async def run(self, ctx: RequestContext) -> None:
        try:
            await self._audit.record_started(ctx)
        except AuditUnavailable:
            ctx.deny(
                ReasonCode.DENIED_AUDIT_UNAVAILABLE,
                "the call was not forwarded because it could not be recorded in the audit log",
            )


def audit_finish_hook(audit: AuditLog) -> FinishHook:
    """The finish hook that closes out every request."""

    async def hook(ctx: RequestContext) -> None:
        await audit.record_outcome(ctx)

    hook.__name__ = "audit_finish"
    return hook


__all__ = ["AuditWriteAhead", "audit_finish_hook"]
