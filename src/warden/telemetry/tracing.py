"""OpenTelemetry tracing for the gateway.

Two things the SDK already does, which this builds on rather than duplicates:

* **The root span.** `mcp.server._otel.OpenTelemetryMiddleware` is installed by default on the
  low-level `Server`, so every inbound request already gets a SERVER span carrying the current
  conventions: `mcp.method.name`, `mcp.protocol.version`, `jsonrpc.request.id`, and for a tool
  call `gen_ai.operation.name = "execute_tool"` with `gen_ai.tool.name`.
* **Context propagation to upstreams.** The SDK's JSON-RPC dispatcher injects W3C
  `traceparent` into outbound `_meta`, so an upstream that also runs the SDK joins the same
  trace with no work from us. There is a test that asserts it rather than an implementation
  that assumes it.

What is left, and what this module adds, is the inside of the gateway: one child span per
pipeline stage and one for the upstream call, carrying the security decision.

**No argument, result or credential ever becomes a span attribute.** Spans travel to a
collector that is usually outside the trust boundary the audit log sits inside, and an
attribute is not redacted by anything downstream. Only names, codes and sizes go on a span;
there is a canary test for it.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from typing import Any, Final

from opentelemetry import trace
from opentelemetry.trace import Span, SpanKind, Status, StatusCode

from warden.config import Settings
from warden.logging import get_logger, span_id_var, trace_id_var

logger = get_logger(__name__)

TRACER_NAME: Final = "warden.gateway"

# Attribute names. The `gen_ai.*` and `mcp.*` ones match what the SDK emits, so a trace reads
# consistently end to end; `warden.*` carries what only this gateway knows.
ATTR_TOOL: Final = "gen_ai.tool.name"
ATTR_METHOD: Final = "mcp.method.name"
ATTR_STAGE: Final = "warden.stage"
ATTR_REQUEST_ID: Final = "warden.request.id"
ATTR_PRINCIPAL: Final = "warden.principal.id"
ATTR_AUTH_METHOD: Final = "warden.auth.method"
ATTR_DECISION: Final = "warden.decision"
ATTR_REASON: Final = "warden.reason_code"
ATTR_RULE: Final = "warden.matched_rule"
ATTR_RISK: Final = "warden.risk"
ATTR_UPSTREAM: Final = "warden.upstream"
ATTR_RESULT_BYTES: Final = "warden.result.bytes"
ATTR_FORWARDED: Final = "warden.forwarded"
ATTR_SCAN_VERDICT: Final = "warden.scan.verdict"
ATTR_SCAN_RULES: Final = "warden.scan.rules"
ATTR_CLASSIFIER_SCORE: Final = "warden.classifier.score"
ATTR_APPROVAL_ID: Final = "warden.approval.id"
ATTR_QUARANTINE_REASON: Final = "warden.quarantine.reason"

#: Every attribute this gateway is allowed to set. A test asserts that nothing outside this set
#: appears on a span, which is what stops an argument from being added "just for debugging".
ALLOWED_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {
        ATTR_TOOL,
        ATTR_METHOD,
        ATTR_STAGE,
        ATTR_REQUEST_ID,
        ATTR_PRINCIPAL,
        ATTR_AUTH_METHOD,
        ATTR_DECISION,
        ATTR_REASON,
        ATTR_RULE,
        ATTR_RISK,
        ATTR_UPSTREAM,
        ATTR_RESULT_BYTES,
        ATTR_FORWARDED,
        ATTR_SCAN_VERDICT,
        ATTR_SCAN_RULES,
        ATTR_CLASSIFIER_SCORE,
        ATTR_APPROVAL_ID,
        ATTR_QUARANTINE_REASON,
        "error.type",
    }
)


def configure_tracing(settings: Settings) -> bool:
    """Install a tracer provider exporting to the configured OTLP endpoint.

    Returns True when tracing was set up. `OTEL_ENABLED=false` (the default) leaves the global
    no-op tracer in place, so every `start_span` in this file becomes free and the gateway runs
    with no collector at all.
    """
    if not settings.otel_enabled:
        return False
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:  # pragma: no cover - only without the otel extras
        logger.warning("tracing is enabled but the OpenTelemetry SDK is not installed")
        return False

    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": settings.otel_service_name,
                "service.version": "0.1.0",
            }
        )
    )
    endpoint = settings.otel_exporter_otlp_endpoint.rstrip("/")
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces"))
    )
    trace.set_tracer_provider(provider)
    logger.warning(
        "tracing enabled",
        extra={"warden": {"endpoint": endpoint, "service": settings.otel_service_name}},
    )
    return True


def tracer() -> trace.Tracer:
    return trace.get_tracer(TRACER_NAME)


def set_attributes(span: Span, attributes: dict[str, Any]) -> None:
    """Set only the attributes this gateway is allowed to set, skipping None values.

    The allowlist is enforced here rather than trusted at every call site: one `span.set_
    attribute("args", ...)` added in a hurry would put call arguments into a collector, and
    this is the single place that can refuse it.
    """
    for key, value in attributes.items():
        if value is None:
            continue
        if key not in ALLOWED_ATTRIBUTES:
            logger.error(
                "refusing to set a span attribute that is not on the allowlist",
                extra={"warden": {"attribute": key}},
            )
            continue
        span.set_attribute(key, value)


@contextmanager
def request_span(method: str, tool: str | None, request_id: str) -> Iterator[Span]:
    """The gateway's own span for one request, a child of the SDK's SERVER span.

    Also binds the trace and span ids to the logging context, so every log line emitted while
    handling this request carries them and a log can be followed into its trace.
    """
    name = f"warden {method}" if tool is None else f"warden {method} {tool}"
    with tracer().start_as_current_span(name, kind=SpanKind.INTERNAL) as span:
        set_attributes(span, {ATTR_METHOD: method, ATTR_TOOL: tool, ATTR_REQUEST_ID: request_id})
        context = span.get_span_context()
        trace_token = trace_id_var.set(format(context.trace_id, "032x"))
        span_token = span_id_var.set(format(context.span_id, "016x"))
        try:
            yield span
        finally:
            trace_id_var.reset(trace_token)
            span_id_var.reset(span_token)


def stage_span(stage: str, tool: str | None) -> Any:
    """A child span for one pipeline stage, or a no-op when tracing is off."""
    if not _tracing_active():
        return nullcontext()
    return _stage_span(stage, tool)


@contextmanager
def _stage_span(stage: str, tool: str | None) -> Iterator[Span]:
    with tracer().start_as_current_span(f"stage {stage}", kind=SpanKind.INTERNAL) as span:
        set_attributes(span, {ATTR_STAGE: stage, ATTR_TOOL: tool})
        yield span


def _tracing_active() -> bool:
    """True when a real tracer provider is installed.

    Checked so the hot path does not build span objects that go nowhere. The default provider
    is a no-op, but entering its context manager is still work per stage per request.
    """
    provider = trace.get_tracer_provider()
    return provider.__class__.__name__ not in ("NoOpTracerProvider", "DefaultTracerProvider")


def record_outcome(span: Span, ctx: Any) -> None:
    """Put the pipeline's decision on the request span.

    Only names, codes and sizes - never an argument, a result or a credential.
    """
    from warden.pipeline import Decision

    scan = ctx.scan_flags or {}
    output = scan.get("output") or {}
    dlp = scan.get("dlp") or {}
    verdict = output.get("verdict") or dlp.get("verdict")
    rules = output.get("rules") or dlp.get("rules") or []
    classifier_score = output.get("classifier_score")

    set_attributes(
        span,
        {
            ATTR_TOOL: ctx.tool_name,
            ATTR_UPSTREAM: ctx.upstream,
            ATTR_PRINCIPAL: ctx.principal.user_id if ctx.principal else None,
            ATTR_AUTH_METHOD: ctx.principal.auth_method if ctx.principal else None,
            ATTR_DECISION: str(ctx.decision),
            ATTR_REASON: str(ctx.reason_code),
            ATTR_RULE: ctx.matched_rule,
            ATTR_RISK: str(ctx.risk),
            ATTR_RESULT_BYTES: ctx.result_bytes,
            ATTR_FORWARDED: ctx.forwarded,
            ATTR_SCAN_VERDICT: verdict,
            ATTR_SCAN_RULES: ",".join(rules) if rules else None,
            ATTR_CLASSIFIER_SCORE: classifier_score,
            ATTR_APPROVAL_ID: ctx.approval_id,
            ATTR_QUARANTINE_REASON: scan.get("quarantine_reason"),
        },
    )
    if ctx.decision is Decision.DENY:
        span.set_attribute("error.type", str(ctx.reason_code))
        span.set_status(Status(StatusCode.ERROR, str(ctx.reason_code)))


__all__ = [
    "ALLOWED_ATTRIBUTES",
    "ATTR_DECISION",
    "ATTR_PRINCIPAL",
    "ATTR_REASON",
    "ATTR_STAGE",
    "ATTR_TOOL",
    "TRACER_NAME",
    "configure_tracing",
    "record_outcome",
    "request_span",
    "set_attributes",
    "stage_span",
    "tracer",
]
