"""The Policy pipeline stage."""

from __future__ import annotations

from warden.errors import ReasonCode
from warden.logging import get_logger
from warden.pipeline import RequestContext
from warden.policy.store import PolicyStore

logger = get_logger(__name__)


class Policy:
    """Apply the policy in force to this call.

    Reads the engine from the store on every request, so a hot reload takes effect on the next
    call rather than on the next restart.
    """

    name = "policy"

    def __init__(self, store: PolicyStore) -> None:
        self._store = store

    async def run(self, ctx: RequestContext) -> None:
        if ctx.tool_name is None:  # pragma: no cover - resolve runs first
            ctx.deny(ReasonCode.DENIED_POLICY, "no tool name to authorise")
            return
        decision = self._store.engine.evaluate(ctx.principal, ctx.tool_name, ctx.arguments)
        ctx.risk = decision.risk
        ctx.matched_rule = decision.rule_id
        if decision.denied:
            ctx.deny(ReasonCode.DENIED_POLICY, decision.reason, rule=decision.rule_id)
            return
        ctx.requires_approval = decision.requires_approval


__all__ = ["Policy"]
