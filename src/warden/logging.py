"""JSON logging with request-id correlation and secret redaction.

`redact()` is the single place that decides what must never reach a log line, an audit row,
a span attribute or an HTTP response. Hard rule 2 depends on it.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any, Final

REDACTED: Final = "[REDACTED]"

#: Terms that make a mapping key secret-bearing. A key is secret when one of its name segments
#: is one of these, or when several consecutive segments spell one out ("api_key", "apiKey",
#: "API-KEY"). Matching segments rather than raw substrings is what keeps "tokens_used" and
#: "secretary" from being treated as credentials while "auth_token" still is.
SECRET_TERMS: Final[tuple[tuple[str, ...], ...]] = (
    ("authorization",),
    ("auth", "token"),
    ("access", "token"),
    ("refresh", "token"),
    ("id", "token"),
    ("bearer",),
    ("token",),
    ("tokens",),
    ("password",),
    ("passwords",),
    ("passwd",),
    ("secret",),
    ("secrets",),
    ("api", "key"),
    ("apikey",),
    ("private", "key"),
    ("privatekey",),
    ("credential",),
    ("credentials",),
    ("cookie",),
    ("cookies",),
    ("client", "secret"),
    ("signature",),
    ("session", "key"),
)

_SEGMENT_SPLIT_RE: Final = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")

MAX_REDACT_DEPTH: Final = 12

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "warden_request_id", default=None
)
principal_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "warden_principal_id", default=None
)
trace_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "warden_trace_id", default=None
)
span_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "warden_span_id", default=None
)


def key_segments(key: str) -> tuple[str, ...]:
    """Split a mapping key into lowercase name segments ("X-Api-Key" -> ("x", "api", "key"))."""
    return tuple(part.lower() for part in _SEGMENT_SPLIT_RE.split(key) if part)


def is_secret_key(key: str) -> bool:
    """True if a mapping key names something that must never be stored or logged.

    Over-matching is deliberate: a redacted field that was harmless costs us one piece of
    debugging context, while a leaked credential is unrecoverable.
    """
    segments = key_segments(key)
    for term in SECRET_TERMS:
        width = len(term)
        for start in range(len(segments) - width + 1):
            if segments[start : start + width] == term:
                return True
    return False


def redact(value: Any, _depth: int = 0) -> Any:
    """Return `value` with every secret-keyed entry replaced by a fixed marker.

    Walks mappings and sequences. Keys are matched by name, so the value never has to be
    pattern-matched, which is what makes the result safe for any value type. Depth is capped so
    a self-referential structure cannot hang the logger; beyond the cap everything is redacted.
    """
    if _depth > MAX_REDACT_DEPTH:
        return REDACTED
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            out[key] = REDACTED if is_secret_key(key) else redact(item, _depth + 1)
        return out
    if isinstance(value, str | bytes | bytearray):
        return value
    if isinstance(value, Sequence):
        return [redact(item, _depth + 1) for item in value]
    if isinstance(value, set | frozenset):
        return [redact(item, _depth + 1) for item in sorted(value, key=repr)]
    return value


class JsonFormatter(logging.Formatter):
    """Render a log record as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for name, var in (
            ("request_id", request_id_var),
            ("principal_id", principal_id_var),
            ("trace_id", trace_id_var),
            ("span_id", span_id_var),
        ):
            current = var.get()
            if current is not None:
                payload[name] = current
        extra = getattr(record, "warden", None)
        if isinstance(extra, Mapping):
            payload.update(redact(dict(extra)))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: str = "INFO", *, stream: Any | None = None) -> None:
    """Install the JSON formatter on the root logger. Idempotent."""
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())
    # These are chatty and say nothing we do not already log ourselves.
    logging.getLogger("httpx").setLevel("WARNING")
    logging.getLogger("httpcore").setLevel("WARNING")


def get_logger(name: str) -> logging.Logger:
    """Return a logger. Use `logger.info("msg", extra={"warden": {...}})` for structured fields."""
    return logging.getLogger(name)
