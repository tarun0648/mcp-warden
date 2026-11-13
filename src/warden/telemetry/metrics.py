"""Prometheus metrics.

Label choices are the whole design here, because a label with unbounded values turns a metrics
endpoint into a memory leak:

* `tool` is bounded - it comes from the registry, and an unknown tool is recorded as the
  literal `"unknown"` rather than whatever the caller sent. Without that, a caller could invent
  a million tool names and create a million time series.
* `reason` is bounded - it is a `ReasonCode`, an enum.
* `principal` is **not** a label at all. It is unbounded by definition, and per-caller usage is
  already available from the audit log and `/admin/usage`, where it belongs.
"""

from __future__ import annotations

from typing import Any, Final

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from warden.logging import get_logger

logger = get_logger(__name__)

UNKNOWN_TOOL_LABEL: Final = "unknown"

#: Buckets chosen for this gateway's shape: stages are sub-millisecond to a few milliseconds,
#: an upstream call is milliseconds to seconds, and an approval wait is tens of seconds.
STAGE_BUCKETS: Final = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0)
UPSTREAM_BUCKETS: Final = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
CLASSIFIER_BUCKETS: Final = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0)


class Metrics:
    """Every metric the gateway exports, on its own registry.

    A dedicated registry rather than the global default: two gateways in one test process would
    otherwise collide on metric names, and a test that asserts a counter moved needs to know
    which gateway moved it.
    """

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()

        self.requests = Counter(
            "warden_requests_total",
            "MCP requests the gateway decided, by outcome.",
            ["decision", "reason", "tool"],
            registry=self.registry,
        )
        self.stage_duration = Histogram(
            "warden_stage_duration_seconds",
            "Time spent in each pipeline stage.",
            ["stage"],
            buckets=STAGE_BUCKETS,
            registry=self.registry,
        )
        self.upstream_duration = Histogram(
            "warden_upstream_duration_seconds",
            "Time spent calling an upstream MCP server.",
            ["upstream"],
            buckets=UPSTREAM_BUCKETS,
            registry=self.registry,
        )
        self.upstream_up = Gauge(
            "warden_upstream_up",
            "1 when an upstream is connected and serving tools, 0 otherwise.",
            ["upstream"],
            registry=self.registry,
        )
        self.upstream_tools = Gauge(
            "warden_upstream_tools",
            "Tools an upstream currently advertises.",
            ["upstream"],
            registry=self.registry,
        )
        self.quarantined_tools = Gauge(
            "warden_quarantined_tools",
            "Tools quarantined and awaiting an admin's approval.",
            registry=self.registry,
        )
        self.pending_approvals = Gauge(
            "warden_pending_approvals",
            "Calls waiting for a human to approve them.",
            registry=self.registry,
        )
        self.classifier_seconds = Histogram(
            "warden_classifier_seconds",
            "Time spent in the local injection classifier.",
            buckets=CLASSIFIER_BUCKETS,
            registry=self.registry,
        )
        self.denials = Counter(
            "warden_denials_total",
            "Denials by reason, for an at-a-glance view of what the gateway is refusing.",
            ["reason"],
            registry=self.registry,
        )

    # -- recording -----------------------------------------------------------------------

    def record_request(self, ctx: Any, known_tools: Any | None = None) -> None:
        """Record one finished request. Safe to call from a pipeline finish hook."""
        from warden.pipeline import Decision

        tool = self._tool_label(ctx.tool_name, known_tools)
        self.requests.labels(
            decision=str(ctx.decision), reason=str(ctx.reason_code), tool=tool
        ).inc()
        if ctx.decision is Decision.DENY:
            self.denials.labels(reason=str(ctx.reason_code)).inc()
        for stage, milliseconds in (ctx.stage_timings_ms or {}).items():
            self.stage_duration.labels(stage=stage).observe(milliseconds / 1000.0)
        forward_ms = (ctx.stage_timings_ms or {}).get("forward")
        if forward_ms is not None and ctx.upstream:
            self.upstream_duration.labels(upstream=ctx.upstream).observe(forward_ms / 1000.0)

    @staticmethod
    def _tool_label(tool: str | None, known_tools: Any | None) -> str:
        """Collapse anything not in the registry to one label value.

        This is the cardinality guard: a caller inventing tool names must not be able to create
        a time series per name.
        """
        if not tool:
            return UNKNOWN_TOOL_LABEL
        if known_tools is None:
            return tool
        try:
            return tool if tool in known_tools else UNKNOWN_TOOL_LABEL
        except TypeError:  # pragma: no cover - a registry that is not a container
            return UNKNOWN_TOOL_LABEL

    def observe_classifier(self, seconds: float) -> None:
        self.classifier_seconds.observe(seconds)

    def set_upstream_health(self, health: Any) -> None:
        for name, status in health.items():
            self.upstream_up.labels(upstream=name).set(1 if status.state == "up" else 0)
            self.upstream_tools.labels(upstream=name).set(status.tool_count)

    def set_quarantined(self, count: int) -> None:
        self.quarantined_tools.set(count)

    def set_pending_approvals(self, count: int) -> None:
        self.pending_approvals.set(count)

    # -- exposing ------------------------------------------------------------------------

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST


__all__ = [
    "CLASSIFIER_BUCKETS",
    "STAGE_BUCKETS",
    "UNKNOWN_TOOL_LABEL",
    "UPSTREAM_BUCKETS",
    "Metrics",
]
