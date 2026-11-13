"""Shared error types and the canonical set of warden reason codes."""

from __future__ import annotations

from enum import StrEnum


class ConfigError(Exception):
    """A configuration file is missing, unreadable or invalid.

    The message always names the file, the key and the problem so an operator can fix it
    without reading our source.
    """

    def __init__(self, file: str, key: str | None, problem: str) -> None:
        self.file = file
        self.key = key
        self.problem = problem
        where = f"{file}" if key is None else f"{file} at key '{key}'"
        super().__init__(f"invalid configuration in {where}: {problem}")


class ReasonCode(StrEnum):
    """Reason codes returned to clients and written to the audit log.

    `WARDEN_DENIED:*` means the pipeline refused the call. `WARDEN_PENDING:*` means the call
    was neither run nor refused yet. `WARDEN_UPSTREAM_*` means the upstream failed.
    """

    # Denials decided by the gateway.
    DENIED_AUTH = "WARDEN_DENIED:auth"
    DENIED_POLICY = "WARDEN_DENIED:policy"
    DENIED_QUARANTINED = "WARDEN_DENIED:quarantined"
    DENIED_RATE_LIMIT = "WARDEN_DENIED:rate_limit"
    DENIED_BUDGET = "WARDEN_DENIED:budget"
    DENIED_LIMITER_UNAVAILABLE = "WARDEN_DENIED:limiter_unavailable"
    DENIED_AUDIT_UNAVAILABLE = "WARDEN_DENIED:audit_unavailable"
    DENIED_DLP = "WARDEN_DENIED:dlp"
    DENIED_INJECTION = "WARDEN_DENIED:injection"
    DENIED_OUTPUT_TOO_LARGE = "WARDEN_DENIED:output_too_large"
    DENIED_APPROVAL_DENIED = "WARDEN_DENIED:approval_denied"
    DENIED_APPROVAL_UNAVAILABLE = "WARDEN_DENIED:approval_unavailable"
    DENIED_SCANNER_ERROR = "WARDEN_DENIED:scanner_error"
    DENIED_INTERNAL = "WARDEN_DENIED:internal"

    # Not a denial: the caller may retry.
    PENDING_APPROVAL = "WARDEN_PENDING:approval"

    # Problems reaching or running the upstream tool.
    UNKNOWN_TOOL = "WARDEN_UNKNOWN_TOOL"
    UPSTREAM_UNAVAILABLE = "WARDEN_UPSTREAM_UNAVAILABLE"
    UPSTREAM_TIMEOUT = "WARDEN_UPSTREAM_TIMEOUT"
    UPSTREAM_ERROR = "WARDEN_UPSTREAM_ERROR"

    # Nothing went wrong.
    ALLOWED = "WARDEN_ALLOWED"
