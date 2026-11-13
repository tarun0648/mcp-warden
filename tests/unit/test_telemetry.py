"""Tracing and metrics, with an in-memory exporter so no collector is involved."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from warden.config import Risk
from warden.errors import ReasonCode
from warden.pipeline import Pipeline, Principal, RequestContext
from warden.telemetry.metrics import UNKNOWN_TOOL_LABEL, Metrics
from warden.telemetry.tracing import (
    ALLOWED_ATTRIBUTES,
    ATTR_DECISION,
    ATTR_REASON,
    ATTR_STAGE,
    ATTR_TOOL,
    record_outcome,
    request_span,
    set_attributes,
)

pytestmark = pytest.mark.unit

CANARY = "wdn_canary_must_not_be_traced_0123"


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    """Install a real tracer provider that keeps spans in memory, then put it back.

    `trace.set_tracer_provider` refuses to replace an existing provider, so the module slot is
    set directly - and the *raw* previous value is restored, not the result of
    `get_tracer_provider()`. That accessor returns a proxy when nothing is set, and putting the
    proxy back into the slot it proxies makes every later lookup recurse until the stack ends.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    previous = getattr(trace, "_TRACER_PROVIDER", None)
    trace._TRACER_PROVIDER = provider  # type: ignore[attr-defined]
    try:
        yield exporter
    finally:
        trace._TRACER_PROVIDER = previous  # type: ignore[attr-defined]


def context(**overrides: Any) -> RequestContext:
    defaults: dict[str, Any] = {
        "method": "tools/call",
        "tool_name": "files__read_file",
        "upstream": "files",
        "principal": Principal(
            user_id="editor-user", roles=("editor",), auth_method="api_key", credential_id="pfx"
        ),
        "arguments": {"path": "a.md", "api_key": CANARY},
        "risk": Risk.READ,
    }
    defaults.update(overrides)
    return RequestContext(**defaults)


class Recorder:
    def __init__(self, name: str) -> None:
        self.name = name

    async def run(self, ctx: RequestContext) -> None:
        return None


class Denier:
    name = "policy"

    async def run(self, ctx: RequestContext) -> None:
        ctx.deny(ReasonCode.DENIED_POLICY, "no", rule="reader-no-sql")


# -- tracing -----------------------------------------------------------------------------------


async def test_an_allowed_call_produces_stage_spans_in_pipeline_order(
    spans: InMemorySpanExporter,
) -> None:
    ctx = context()
    stages = [Recorder("authenticate"), Recorder("policy"), Recorder("forward")]
    with request_span("tools/call", ctx.tool_name, ctx.request_id) as span:
        await Pipeline(stages).run(ctx)
        record_outcome(span, ctx)

    finished = spans.get_finished_spans()
    stage_names = [
        s.attributes[ATTR_STAGE] for s in finished if s.attributes and ATTR_STAGE in s.attributes
    ]
    assert stage_names == ["authenticate", "policy", "forward"], stage_names
    root = next(s for s in finished if s.name.startswith("warden tools/call"))
    assert root.attributes is not None
    assert root.attributes[ATTR_DECISION] == "allow"
    assert root.attributes[ATTR_REASON] == "WARDEN_ALLOWED"
    assert root.attributes[ATTR_TOOL] == "files__read_file"


async def test_every_span_shares_one_trace(spans: InMemorySpanExporter) -> None:
    ctx = context()
    with request_span("tools/call", ctx.tool_name, ctx.request_id):
        await Pipeline([Recorder("a"), Recorder("b")]).run(ctx)
    trace_ids = {s.context.trace_id for s in spans.get_finished_spans() if s.context}
    assert len(trace_ids) == 1, "the stage spans must be children of the request span"


async def test_a_denial_stops_the_trace_at_the_stage_that_refused(
    spans: InMemorySpanExporter,
) -> None:
    ctx = context()
    stages = [Recorder("authenticate"), Denier(), Recorder("forward")]
    with request_span("tools/call", ctx.tool_name, ctx.request_id) as span:
        await Pipeline(stages).run(ctx)
        record_outcome(span, ctx)

    finished = spans.get_finished_spans()
    stage_names = [
        s.attributes[ATTR_STAGE] for s in finished if s.attributes and ATTR_STAGE in s.attributes
    ]
    assert stage_names == ["authenticate", "policy"], "no span after the denial"

    policy = next(s for s in finished if s.attributes and s.attributes.get(ATTR_STAGE) == "policy")
    assert policy.attributes is not None
    assert policy.attributes[ATTR_REASON] == "WARDEN_DENIED:policy"

    root = next(s for s in finished if s.name.startswith("warden tools/call"))
    assert root.attributes is not None
    assert root.attributes[ATTR_REASON] == "WARDEN_DENIED:policy"
    assert root.attributes["error.type"] == "WARDEN_DENIED:policy"
    assert root.status.status_code.name == "ERROR"


async def test_the_outcome_span_carries_the_security_decision(
    spans: InMemorySpanExporter,
) -> None:
    ctx = context(risk=Risk.DESTRUCTIVE)
    ctx.matched_rule = "editor-files-delete"
    ctx.approval_id = "appr-123"
    ctx.forwarded = True
    ctx.result_bytes = 42
    ctx.scan_flags = {
        "output": {
            "verdict": "suspicious",
            "rules": ["instruction:system_prompt"],
            "classifier_score": 0.42,
        },
        "quarantine_reason": None,
    }
    with request_span("tools/call", ctx.tool_name, ctx.request_id) as span:
        record_outcome(span, ctx)
    root = spans.get_finished_spans()[0]
    assert root.attributes is not None
    assert root.attributes["warden.risk"] == "destructive"
    assert root.attributes["warden.matched_rule"] == "editor-files-delete"
    assert root.attributes["warden.approval.id"] == "appr-123"
    assert root.attributes["warden.result.bytes"] == 42
    assert root.attributes["warden.forwarded"] is True
    assert root.attributes["warden.scan.verdict"] == "suspicious"
    assert root.attributes["warden.scan.rules"] == "instruction:system_prompt"
    assert root.attributes["warden.classifier.score"] == pytest.approx(0.42)


async def test_the_request_span_binds_trace_ids_to_the_log_context(
    spans: InMemorySpanExporter,
) -> None:
    """So a log line can be followed into its trace."""
    from warden.logging import span_id_var, trace_id_var

    assert trace_id_var.get() is None
    with request_span("tools/call", "files__read_file", "req-1"):
        bound_trace = trace_id_var.get()
        bound_span = span_id_var.get()
        assert bound_trace is not None and len(bound_trace) == 32
        assert bound_span is not None and len(bound_span) == 16
    assert trace_id_var.get() is None, "the binding must not leak past the request"


# -- the canary --------------------------------------------------------------------------------


async def test_no_argument_or_credential_ever_reaches_a_span(
    spans: InMemorySpanExporter,
) -> None:
    """Spans leave the trust boundary the audit log sits inside, and nothing redacts them."""
    ctx = context(arguments={"path": "a.md", "api_key": CANARY, "body": CANARY})
    ctx.result_bytes = 10
    ctx.scan_flags = {"dlp": {"verdict": "malicious", "rules": ["dlp:canary"]}}
    with request_span("tools/call", ctx.tool_name, ctx.request_id) as span:
        await Pipeline([Recorder("dlp")]).run(ctx)
        record_outcome(span, ctx)

    rendered = repr(
        [
            (s.name, dict(s.attributes or {}), [dict(e.attributes or {}) for e in s.events])
            for s in spans.get_finished_spans()
        ]
    )
    assert CANARY not in rendered
    assert "a.md" not in rendered, "even a harmless argument value stays off the span"


async def test_an_attribute_outside_the_allowlist_is_refused(
    spans: InMemorySpanExporter,
) -> None:
    """The allowlist is the single place that can stop a stray debugging attribute."""
    with request_span("tools/call", "files__read_file", "req-1") as span:
        set_attributes(span, {"warden.arguments": CANARY, ATTR_TOOL: "files__read_file"})
    root = spans.get_finished_spans()[0]
    assert root.attributes is not None
    assert "warden.arguments" not in root.attributes
    assert root.attributes[ATTR_TOOL] == "files__read_file"
    assert CANARY not in repr(dict(root.attributes))


def test_the_allowlist_contains_nothing_that_could_hold_content() -> None:
    forbidden = ("argument", "args", "result", "content", "body", "token", "credential", "key")
    for attribute in ALLOWED_ATTRIBUTES:
        if attribute in ("gen_ai.tool.name", "warden.approval.id", "warden.matched_rule"):
            continue
        for word in forbidden:
            assert word not in attribute.lower() or attribute.endswith(".bytes"), attribute


# -- tracing off -------------------------------------------------------------------------------


async def test_stages_still_run_with_tracing_disabled() -> None:
    """The default. `stage_span` becomes a no-op and nothing else changes."""
    ctx = context()
    result = await Pipeline([Recorder("a"), Recorder("b")]).run(ctx)
    assert set(result.stage_timings_ms) == {"a", "b"}


def test_configure_tracing_is_a_no_op_when_disabled(settings: Any) -> None:
    from warden.telemetry.tracing import configure_tracing

    assert configure_tracing(settings) is False


# -- metrics -----------------------------------------------------------------------------------


def sample(metrics: Metrics, name: str, **labels: str) -> float:
    value = metrics.registry.get_sample_value(name, labels or None)
    return 0.0 if value is None else float(value)


async def test_an_allowed_request_increments_the_counter() -> None:
    metrics = Metrics()
    ctx = context()
    ctx.stage_timings_ms = {"policy": 1.5, "forward": 20.0}
    metrics.record_request(ctx, known_tools={"files__read_file"})
    assert (
        sample(
            metrics,
            "warden_requests_total",
            decision="allow",
            reason="WARDEN_ALLOWED",
            tool="files__read_file",
        )
        == 1.0
    )
    assert sample(metrics, "warden_stage_duration_seconds_count", stage="policy") == 1.0
    assert sample(metrics, "warden_upstream_duration_seconds_count", upstream="files") == 1.0
    assert sample(
        metrics, "warden_upstream_duration_seconds_sum", upstream="files"
    ) == pytest.approx(0.02)


async def test_a_denial_increments_both_counters() -> None:
    metrics = Metrics()
    ctx = context()
    ctx.deny(ReasonCode.DENIED_POLICY, "no")
    metrics.record_request(ctx, known_tools={"files__read_file"})
    assert (
        sample(
            metrics,
            "warden_requests_total",
            decision="deny",
            reason="WARDEN_DENIED:policy",
            tool="files__read_file",
        )
        == 1.0
    )
    assert sample(metrics, "warden_denials_total", reason="WARDEN_DENIED:policy") == 1.0


async def test_an_unknown_tool_is_collapsed_to_one_label() -> None:
    """The cardinality guard: a caller inventing names must not create a series each."""
    metrics = Metrics()
    known = {"files__read_file"}
    for index in range(50):
        ctx = context(tool_name=f"made__up{index}")
        ctx.deny(ReasonCode.UNKNOWN_TOOL, "no such tool")
        metrics.record_request(ctx, known_tools=known)
    assert (
        sample(
            metrics,
            "warden_requests_total",
            decision="deny",
            reason="WARDEN_UNKNOWN_TOOL",
            tool=UNKNOWN_TOOL_LABEL,
        )
        == 50.0
    )
    rendered = metrics.render()[0].decode()
    assert "made__up0" not in rendered


async def test_a_missing_tool_name_is_labelled_unknown() -> None:
    metrics = Metrics()
    ctx = context(tool_name=None)
    metrics.record_request(ctx, known_tools={"files__read_file"})
    assert (
        sample(
            metrics,
            "warden_requests_total",
            decision="allow",
            reason="WARDEN_ALLOWED",
            tool=UNKNOWN_TOOL_LABEL,
        )
        == 1.0
    )


def test_no_metric_is_labelled_by_principal() -> None:
    """Per-caller usage belongs in the audit log, not in unbounded label values."""
    metrics = Metrics()
    rendered = metrics.render()[0].decode()
    assert "principal" not in rendered
    assert "user" not in rendered


def test_gauges_are_settable() -> None:
    metrics = Metrics()
    metrics.set_quarantined(4)
    metrics.set_pending_approvals(2)
    metrics.observe_classifier(0.05)
    assert sample(metrics, "warden_quarantined_tools") == 4.0
    assert sample(metrics, "warden_pending_approvals") == 2.0
    assert sample(metrics, "warden_classifier_seconds_count") == 1.0


def test_upstream_health_becomes_gauges() -> None:
    from warden.upstream.manager import UpstreamHealth, UpstreamState

    metrics = Metrics()
    metrics.set_upstream_health(
        {
            "files": UpstreamHealth(name="files", state=UpstreamState.UP, tool_count=4),
            "evil": UpstreamHealth(name="evil", state=UpstreamState.DOWN, tool_count=0),
        }
    )
    assert sample(metrics, "warden_upstream_up", upstream="files") == 1.0
    assert sample(metrics, "warden_upstream_up", upstream="evil") == 0.0
    assert sample(metrics, "warden_upstream_tools", upstream="files") == 4.0


def test_two_registries_do_not_collide() -> None:
    """Which is why the gateway does not use the global default registry."""
    first, second = Metrics(), Metrics()
    ctx = context()
    first.record_request(ctx, known_tools={"files__read_file"})
    assert (
        sample(
            first,
            "warden_requests_total",
            decision="allow",
            reason="WARDEN_ALLOWED",
            tool="files__read_file",
        )
        == 1.0
    )
    assert (
        sample(
            second,
            "warden_requests_total",
            decision="allow",
            reason="WARDEN_ALLOWED",
            tool="files__read_file",
        )
        == 0.0
    )


def test_render_produces_prometheus_text() -> None:
    metrics = Metrics()
    metrics.set_quarantined(1)
    body, content_type = metrics.render()
    assert content_type.startswith("text/plain")
    text = body.decode()
    assert "# HELP warden_quarantined_tools" in text
    assert "warden_quarantined_tools 1.0" in text


# -- classifier timings ------------------------------------------------------------------------


async def test_classifier_timings_reach_the_histogram() -> None:
    """Otherwise the "classifier latency" panel is permanently empty."""
    from warden.scan.classifier import InjectionClassifier

    metrics = Metrics()

    class FakePipeline:
        def __call__(self, text: str) -> Any:
            return [{"label": "INJECTION", "score": 0.1}]

    classifier = InjectionClassifier(
        enabled=True, timeout_seconds=5.0, on_timing=metrics.observe_classifier
    )
    classifier._pipeline = FakePipeline()  # type: ignore[attr-defined]
    await classifier.classify("some text")
    assert sample(metrics, "warden_classifier_seconds_count") == 1.0
    assert sample(metrics, "warden_classifier_seconds_sum") > 0.0


async def test_a_classifier_timeout_is_still_timed() -> None:
    """A timeout is the most interesting measurement, so it must not be dropped."""
    import time as _time

    from warden.scan.classifier import InjectionClassifier

    metrics = Metrics()

    class SlowPipeline:
        def __call__(self, text: str) -> Any:
            _time.sleep(0.5)
            return [{"label": "INJECTION", "score": 0.1}]

    classifier = InjectionClassifier(
        enabled=True, timeout_seconds=0.05, on_timing=metrics.observe_classifier
    )
    classifier._pipeline = SlowPipeline()  # type: ignore[attr-defined]
    result = await classifier.classify("some text")
    assert result.failed
    assert sample(metrics, "warden_classifier_seconds_count") == 1.0


async def test_a_broken_timing_hook_does_not_fail_the_classification() -> None:
    from warden.scan.classifier import InjectionClassifier

    def explode(seconds: float) -> None:
        raise RuntimeError("metrics are down")

    class FakePipeline:
        def __call__(self, text: str) -> Any:
            return [{"label": "INJECTION", "score": 0.9}]

    classifier = InjectionClassifier(enabled=True, timeout_seconds=5.0, on_timing=explode)
    classifier._pipeline = FakePipeline()  # type: ignore[attr-defined]
    result = await classifier.classify("some text")
    assert result.score == pytest.approx(0.9)
    assert not result.failed
