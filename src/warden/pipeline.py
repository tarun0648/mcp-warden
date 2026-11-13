"""The request pipeline: a fixed order of small stages, each able to stop the request.

Every `tools/call` runs through the same list of stages. A stage reads and writes one
`RequestContext` and may set a denial; the pipeline stops at the first one. Whatever happens -
denial, exception, success - the finish hooks always run, because the audit log is one of them
and hard rule 1 says a call that is not recorded did not happen.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from warden.config import Risk
from warden.errors import ReasonCode
from warden.logging import get_logger

if TYPE_CHECKING:
    from mcp_types import CallToolResult

logger = get_logger(__name__)


#: `await progress(step, message)`. Reporting progress is best effort: the client may have
#: gone away, and a failed notification must never fail the request.
ProgressReporter = Callable[[int, str], Awaitable[None]]


class Decision(StrEnum):
    """Where the request stands. Anything but ALLOW stops the pipeline."""

    ALLOW = "allow"
    DENY = "deny"
    PENDING = "pending"


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    user_id: str
    roles: tuple[str, ...]
    auth_method: str
    #: Which credential proved the identity: an API key prefix or a JWT jti. Never the secret.
    credential_id: str

    def has_role(self, role: str) -> bool:
        return role in self.roles


@dataclass(slots=True)
class RequestContext:
    """Everything one request accumulates as it crosses the pipeline.

    Stages only ever add to this. Nothing here may hold a raw credential: `principal` carries a
    credential *identifier*, and `arguments` is redacted before it reaches a log or an audit row.
    """

    method: str
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    principal: Principal | None = None
    tool_name: str | None = None
    upstream: str | None = None
    upstream_tool: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    risk: Risk = Risk.READ
    started_at: float = field(default_factory=time.monotonic)
    stage_timings_ms: dict[str, float] = field(default_factory=dict)
    decision: Decision = Decision.ALLOW
    reason_code: ReasonCode = ReasonCode.ALLOWED
    reason: str | None = None
    matched_rule: str | None = None
    requires_approval: bool = False
    approval_id: str | None = None
    scan_flags: dict[str, Any] = field(default_factory=dict)
    #: Dotted paths into `arguments` whose values must be masked wherever the arguments are
    #: stored. Set by the DLP stage: `redact()` masks by *key name*, so a credential sent under
    #: an innocent key like "body" would otherwise be written to the audit log verbatim - the
    #: very value the gateway just refused to forward.
    redact_paths: set[str] = field(default_factory=set)
    #: Set by the MCP layer when the client sent a progressToken: `await ctx.progress(n, msg)`.
    #: None when the client did not ask for progress, which is most of the time - a stage that
    #: wants to report progress must tolerate its absence.
    progress: ProgressReporter | None = None
    result: CallToolResult | None = None
    result_bytes: int = 0
    #: Set when the upstream actually ran, so the audit log can tell "denied before forwarding"
    #: from "forwarded and then refused".
    forwarded: bool = False

    def deny(self, reason_code: ReasonCode, reason: str, *, rule: str | None = None) -> None:
        """Refuse the request. The first denial wins; a later stage cannot soften it."""
        if self.decision is Decision.DENY:
            return
        self.decision = Decision.DENY
        self.reason_code = reason_code
        self.reason = reason
        if rule is not None:
            self.matched_rule = rule

    def pend(self, reason_code: ReasonCode, reason: str) -> None:
        """Neither allow nor refuse: the caller must come back (human approval is outstanding)."""
        if self.decision is Decision.DENY:
            return
        self.decision = Decision.PENDING
        self.reason_code = reason_code
        self.reason = reason

    @property
    def stopped(self) -> bool:
        return self.decision is not Decision.ALLOW

    @property
    def elapsed_ms(self) -> float:
        return (time.monotonic() - self.started_at) * 1000


@runtime_checkable
class Stage(Protocol):
    """One step of the pipeline.

    `name` is what appears in stage timings, traces and metrics, so it is stable and short.
    `run` either does nothing, enriches the context, or calls `ctx.deny(...)` / `ctx.pend(...)`.
    """

    name: str

    async def run(self, ctx: RequestContext) -> None: ...


#: Called after the pipeline finishes, whatever the outcome. Hooks must not raise; if one does,
#: it is logged and the others still run.
FinishHook = Callable[[RequestContext], Awaitable[None]]


class Pipeline:
    """Runs stages in order, records per-stage timing, and always runs the finish hooks."""

    def __init__(self, stages: Sequence[Stage], finish_hooks: Sequence[FinishHook] = ()) -> None:
        self.stages = list(stages)
        self.finish_hooks = list(finish_hooks)

    @property
    def stage_names(self) -> list[str]:
        return [stage.name for stage in self.stages]

    async def run(self, ctx: RequestContext) -> RequestContext:
        """Run the pipeline over `ctx` and return it.

        An exception inside a stage becomes a denial rather than a 500: a bug in a security
        stage must not turn into an allowed call (hard rule 1).
        """
        try:
            for stage in self.stages:
                if ctx.stopped:
                    break
                started = time.perf_counter()
                try:
                    await stage.run(ctx)
                except Exception:
                    logger.exception(
                        "pipeline stage raised",
                        extra={"warden": {"stage": stage.name, "tool": ctx.tool_name}},
                    )
                    ctx.deny(
                        ReasonCode.DENIED_INTERNAL,
                        f"the {stage.name} stage failed; the call was not forwarded",
                    )
                finally:
                    ctx.stage_timings_ms[stage.name] = (time.perf_counter() - started) * 1000
        finally:
            await self._finish(ctx)
        return ctx

    async def _finish(self, ctx: RequestContext) -> None:
        for hook in self.finish_hooks:
            try:
                await hook(ctx)
            except Exception:
                logger.exception(
                    "pipeline finish hook raised",
                    extra={"warden": {"hook": getattr(hook, "__name__", repr(hook))}},
                )


__all__ = [
    "Decision",
    "FinishHook",
    "Pipeline",
    "Principal",
    "ProgressReporter",
    "RequestContext",
    "Stage",
]
