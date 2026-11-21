"""Running a tool call from the console, through the real pipeline.

The playground exists to show what the gateway does, so it must not be a lookalike: a call
made here crosses the same pipeline instance as a call from an MCP client - authentication
re-assertion, integrity, defaults, policy, rate limits, DLP, approval, the audit write-ahead,
forwarding and output scanning - and is audited like one. The only difference is how the
principal arrived: from a signed-in console session (`auth_method="console"`) rather than a
bearer credential, acting with a role the admin picks.

Acting as another role grants nothing new: an admin can already mint a key for any role. It
is recorded, though - the audit row carries the admin's user id and `auth_method="console"`,
so a call made from here is never mistaken for one a real client made.

Calls run as background tasks because a destructive call may wait for a human approval for up
to `approval.wait_seconds`; the page polls the job instead of holding a request open.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final

from warden.logging import get_logger, request_id_var
from warden.pipeline import Pipeline, Principal, RequestContext
from warden.proxy.stages import denial_result

logger = get_logger(__name__)

#: How many finished jobs are remembered. Old ones are dropped; a job is a page's worth of
#: state, not a record - the audit log is the record.
MAX_JOBS: Final = 50
AUTH_METHOD: Final = "console"


@dataclass(slots=True)
class Job:
    id: str
    owner: str
    tool: str
    role: str
    arguments: dict[str, Any]
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    ctx: RequestContext | None = None
    error: str | None = None
    task: asyncio.Task[None] | None = None

    @property
    def done(self) -> bool:
        return self.finished_at is not None

    @property
    def elapsed_seconds(self) -> float:
        end = self.finished_at if self.finished_at is not None else time.time()
        return end - self.started_at

    def outcome(self) -> dict[str, Any]:
        """What a client would have received, plus what the pipeline knew about it."""
        ctx = self.ctx
        if ctx is None:
            return {"state": "starting"}
        if not self.done:
            return {
                "state": "running",
                "request_id": ctx.request_id,
                "approval_id": ctx.approval_id,
            }
        result = denial_result(ctx) if ctx.stopped or ctx.result is None else ctx.result
        texts = [getattr(block, "text", "") for block in result.content or []]
        return {
            "state": "done",
            "decision": str(ctx.decision),
            "reason_code": str(ctx.reason_code),
            "reason": ctx.reason,
            "matched_rule": ctx.matched_rule,
            "request_id": ctx.request_id,
            "approval_id": ctx.approval_id,
            "is_error": bool(result.is_error),
            "text": "\n".join(text for text in texts if text),
            "structured": result.structured_content,
            "stage_timings_ms": dict(ctx.stage_timings_ms),
            "scan_flags": dict(ctx.scan_flags),
            "arguments_forwarded": dict(ctx.arguments) if ctx.forwarded else None,
            "forwarded": ctx.forwarded,
            "error": self.error,
        }


class JobStore:
    """Jobs by id, bounded, each visible only to the admin who started it."""

    def __init__(self, *, limit: int = MAX_JOBS) -> None:
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._limit = limit

    def add(self, job: Job) -> None:
        """Remember a job, dropping the oldest *finished* ones over the limit.

        A running job is never dropped: its call is still in flight, and losing the handle
        would leave the page unable to show how it ended.
        """
        self._jobs[job.id] = job
        for job_id in list(self._jobs):
            if len(self._jobs) <= self._limit:
                break
            if self._jobs[job_id].done:
                del self._jobs[job_id]

    def get(self, job_id: str, owner: str) -> Job | None:
        job = self._jobs.get(job_id)
        if job is None or job.owner != owner:
            return None
        return job

    def recent(self, owner: str, *, limit: int = 8) -> list[Job]:
        mine = [job for job in reversed(self._jobs.values()) if job.owner == owner]
        return mine[:limit]

    def __len__(self) -> int:
        return len(self._jobs)


def console_principal(user_id: str, role: str) -> Principal:
    return Principal(
        user_id=user_id, roles=(role,), auth_method=AUTH_METHOD, credential_id="console-session"
    )


async def run_job(job: Job, pipeline_factory: Callable[[], Pipeline]) -> None:
    """Run one call to completion. Never raises: an error is recorded on the job."""
    from warden.telemetry.tracing import record_outcome, request_span

    ctx = RequestContext(
        method="tools/call",
        principal=console_principal(job.owner, job.role),
        tool_name=job.tool,
        arguments=dict(job.arguments),
    )
    job.ctx = ctx
    token = request_id_var.set(ctx.request_id)
    try:
        with request_span("tools/call", job.tool, ctx.request_id) as span:
            await pipeline_factory().run(ctx)
            if span is not None:
                record_outcome(span, ctx)
    except Exception as exc:  # the pipeline already fails closed; this is belt and braces
        job.error = f"{type(exc).__name__}: {exc}"[:300]
        logger.exception("console playground call failed")
    finally:
        request_id_var.reset(token)
        job.finished_at = time.time()


def start_job(
    store: JobStore,
    pipeline_factory: Callable[[], Pipeline],
    *,
    owner: str,
    tool: str,
    role: str,
    arguments: dict[str, Any],
) -> Job:
    job = Job(
        id=secrets.token_urlsafe(12),
        owner=owner,
        tool=tool,
        role=role,
        arguments=arguments,
    )
    job.task = asyncio.create_task(run_job(job, pipeline_factory))
    store.add(job)
    return job


async def cancel_all(store: JobStore) -> None:
    """For shutdown: stop any call still waiting, so the process can exit."""
    for job in list(store._jobs.values()):
        if job.task is not None and not job.task.done():
            job.task.cancel()
            with contextlib.suppress(BaseException):
                await job.task


def suggested_arguments(schema: Any) -> dict[str, Any]:
    """A starting point for the arguments box: declared defaults, and blanks for the required."""
    if not isinstance(schema, dict):
        return {}
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    required = set(schema.get("required") or [])
    out: dict[str, Any] = {}
    for name, prop in properties.items():
        if not isinstance(prop, dict):
            continue
        if "default" in prop and prop["default"] is not None:
            out[name] = prop["default"]
        elif name in required:
            out[name] = _blank_for(prop.get("type"))
    return out


def _blank_for(kind: Any) -> Any:
    return {"integer": 0, "number": 0, "boolean": False, "array": [], "object": {}}.get(
        kind if isinstance(kind, str) else "string", ""
    )


__all__ = [
    "AUTH_METHOD",
    "MAX_JOBS",
    "Job",
    "JobStore",
    "cancel_all",
    "console_principal",
    "run_job",
    "start_job",
    "suggested_arguments",
]
