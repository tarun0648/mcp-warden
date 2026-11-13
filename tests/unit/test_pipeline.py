"""The pipeline runner: order, early stop, timings, and finish hooks that always run."""

from __future__ import annotations

import pytest

from warden.errors import ReasonCode
from warden.pipeline import Decision, Pipeline, Principal, RequestContext

pytestmark = pytest.mark.unit


class Recorder:
    """A stage that appends its name to a shared list."""

    def __init__(self, name: str, log: list[str]) -> None:
        self.name = name
        self._log = log

    async def run(self, ctx: RequestContext) -> None:
        self._log.append(self.name)


class Denier:
    name = "denier"

    def __init__(self, log: list[str]) -> None:
        self._log = log

    async def run(self, ctx: RequestContext) -> None:
        self._log.append(self.name)
        ctx.deny(ReasonCode.DENIED_POLICY, "no", rule="rule-1")


class Exploder:
    name = "exploder"

    async def run(self, ctx: RequestContext) -> None:
        raise RuntimeError("stage is broken")


def context() -> RequestContext:
    return RequestContext(method="tools/call", tool_name="files__read_file")


async def test_stages_run_in_order() -> None:
    log: list[str] = []
    pipeline = Pipeline([Recorder("one", log), Recorder("two", log), Recorder("three", log)])
    ctx = await pipeline.run(context())
    assert log == ["one", "two", "three"]
    assert ctx.decision is Decision.ALLOW
    assert pipeline.stage_names == ["one", "two", "three"]


async def test_pipeline_stops_at_the_first_denial() -> None:
    log: list[str] = []
    pipeline = Pipeline([Recorder("one", log), Denier(log), Recorder("three", log)])
    ctx = await pipeline.run(context())
    assert log == ["one", "denier"], "no stage runs after a denial"
    assert ctx.decision is Decision.DENY
    assert ctx.reason_code is ReasonCode.DENIED_POLICY
    assert ctx.matched_rule == "rule-1"


async def test_timings_are_recorded_for_every_stage_that_ran() -> None:
    log: list[str] = []
    pipeline = Pipeline([Recorder("one", log), Denier(log), Recorder("three", log)])
    ctx = await pipeline.run(context())
    assert set(ctx.stage_timings_ms) == {"one", "denier"}
    assert all(value >= 0 for value in ctx.stage_timings_ms.values())
    assert ctx.elapsed_ms >= 0


async def test_a_stage_that_raises_denies_rather_than_allowing() -> None:
    """Hard rule 1: a broken security stage must never result in a forwarded call."""
    log: list[str] = []
    pipeline = Pipeline([Exploder(), Recorder("after", log)])
    ctx = await pipeline.run(context())
    assert ctx.decision is Decision.DENY
    assert ctx.reason_code is ReasonCode.DENIED_INTERNAL
    assert "exploder" in (ctx.reason or "")
    assert log == [], "the pipeline stops after a stage failure"
    assert "exploder" in ctx.stage_timings_ms


async def test_finish_hooks_run_on_success() -> None:
    seen: list[str] = []

    async def hook(ctx: RequestContext) -> None:
        seen.append(str(ctx.reason_code))

    await Pipeline([Recorder("one", [])], [hook]).run(context())
    assert seen == ["WARDEN_ALLOWED"]


async def test_finish_hooks_run_after_a_denial() -> None:
    seen: list[str] = []

    async def hook(ctx: RequestContext) -> None:
        seen.append(str(ctx.reason_code))

    await Pipeline([Denier([])], [hook]).run(context())
    assert seen == ["WARDEN_DENIED:policy"]


async def test_finish_hooks_run_after_a_stage_exception() -> None:
    seen: list[str] = []

    async def hook(ctx: RequestContext) -> None:
        seen.append(str(ctx.reason_code))

    await Pipeline([Exploder()], [hook]).run(context())
    assert seen == ["WARDEN_DENIED:internal"]


async def test_a_failing_finish_hook_does_not_stop_the_others() -> None:
    seen: list[str] = []

    async def broken(ctx: RequestContext) -> None:
        raise RuntimeError("audit writer is down")

    async def good(ctx: RequestContext) -> None:
        seen.append("ran")

    await Pipeline([Recorder("one", [])], [broken, good]).run(context())
    assert seen == ["ran"]


async def test_the_first_denial_wins() -> None:
    ctx = context()
    ctx.deny(ReasonCode.DENIED_POLICY, "first")
    ctx.deny(ReasonCode.DENIED_RATE_LIMIT, "second")
    assert ctx.reason_code is ReasonCode.DENIED_POLICY
    assert ctx.reason == "first"


async def test_a_denial_cannot_be_downgraded_to_pending() -> None:
    ctx = context()
    ctx.deny(ReasonCode.DENIED_DLP, "secret in arguments")
    ctx.pend(ReasonCode.PENDING_APPROVAL, "waiting")
    assert ctx.decision is Decision.DENY
    assert ctx.reason_code is ReasonCode.DENIED_DLP


async def test_pending_stops_the_pipeline_too() -> None:
    log: list[str] = []

    class Pender:
        name = "approval"

        async def run(self, ctx: RequestContext) -> None:
            ctx.pend(ReasonCode.PENDING_APPROVAL, "waiting for a human")

    ctx = await Pipeline([Pender(), Recorder("forward", log)]).run(context())
    assert ctx.decision is Decision.PENDING
    assert log == []
    assert ctx.stopped


def test_request_ids_are_unique() -> None:
    assert context().request_id != context().request_id


def test_principal_roles() -> None:
    principal = Principal(
        user_id="alice", roles=("reader", "editor"), auth_method="api_key", credential_id="wdn_abcd"
    )
    assert principal.has_role("editor")
    assert not principal.has_role("admin")
