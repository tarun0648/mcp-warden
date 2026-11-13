"""Database tables.

Added phase by phase: `api_keys` in Phase 4, `audit_events` in 7, `tool_pins` in 8,
`approvals` in 9.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from warden.db.base import Base, JsonColumn, UtcDateTime, utcnow


class ApiKey(Base):
    """A long-lived gateway credential.

    Only a hash is stored. `key_prefix` is the first 8 characters of the *public* part of the
    key, kept in clear so an operator can name a key in a CLI command and so a lookup does not
    have to scan every row; it is not enough to authenticate with.
    """

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key_sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    roles: Mapped[list[str]] = mapped_column(JsonColumn, nullable=False, default=list)
    label: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    __table_args__ = (
        Index("ix_api_keys_key_prefix", "key_prefix"),
        Index("ix_api_keys_user_id", "user_id"),
    )

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def as_dict(self) -> dict[str, Any]:
        """A safe summary: never includes the hash, which is still a verifier."""
        return {
            "prefix": self.key_prefix,
            "user_id": self.user_id,
            "roles": list(self.roles),
            "label": self.label,
            "created_at": self.created_at.isoformat(),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }


class AuditEvent(Base):
    """One row per observable moment in a request's life.

    An allowed call produces two rows: `started` (written *before* the upstream is reached) and
    `finished`. A call refused before forwarding produces one `denied` row. The pair is what
    makes the log answer "did this actually run?" and not merely "was this permitted?".

    The table is append-only by design and by grant: `prev_hash` and `row_hash` chain the rows
    together, so editing, deleting or reordering any row breaks every hash after it.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    #: started | finished | denied, plus the approval lifecycle events from Phase 9.
    event: Mapped[str] = mapped_column(String(32), nullable=False)

    principal_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    auth_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    method: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str | None] = mapped_column(String(128), nullable=True)
    upstream: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk: Mapped[str | None] = mapped_column(String(16), nullable=True)

    #: Arguments with every secret-keyed value masked by `warden.logging.redact`.
    args_redacted: Mapped[dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    #: SHA-256 of the canonical form of the *raw* arguments. Proves what was sent without
    #: storing it, and is what an approval is bound to.
    args_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    matched_rule: Mapped[str | None] = mapped_column(String(64), nullable=True)

    stage_timings_ms: Mapped[dict[str, Any]] = mapped_column(
        JsonColumn, nullable=False, default=dict
    )
    result_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scan_flags: Mapped[dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    #: The previous row's `row_hash`, or 64 zeroes for the first row.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    __table_args__ = (
        Index("ix_audit_events_ts", "ts"),
        Index("ix_audit_events_request_id", "request_id"),
        Index("ix_audit_events_principal_id", "principal_id"),
        Index("ix_audit_events_tool", "tool"),
        Index("ix_audit_events_decision", "decision"),
    )

    def as_dict(self) -> dict[str, Any]:
        """The row as the admin API returns it."""
        return {
            "id": self.id,
            "ts": self.ts.isoformat(),
            "request_id": self.request_id,
            "event": self.event,
            "principal_id": self.principal_id,
            "auth_method": self.auth_method,
            "method": self.method,
            "tool": self.tool,
            "upstream": self.upstream,
            "risk": self.risk,
            "args_redacted": self.args_redacted,
            "args_sha256": self.args_sha256,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "matched_rule": self.matched_rule,
            "stage_timings_ms": self.stage_timings_ms,
            "result_bytes": self.result_bytes,
            "result_sha256": self.result_sha256,
            "scan_flags": self.scan_flags,
            "prev_hash": self.prev_hash,
            "row_hash": self.row_hash,
        }


class ToolPin(Base):
    """What we have agreed one upstream tool's definition looks like.

    A pin is a promise: this exact definition, by hash, is the one an operator (or the
    auto-pinning rule for a trusted server) accepted. If the upstream later sends a different
    definition, the hash no longer matches and the tool is quarantined - that is the rug pull.

    `status` is the gate. `pinned` tools are listed and callable; `quarantined` tools are hidden
    from `tools/list` and refused on call.
    """

    __tablename__ = "tool_pins"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    server: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(128), nullable=False)
    #: SHA-256 of the canonical JSON of the accepted definition.
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    #: The scan that produced this status, kept so an operator can see *why* it was quarantined
    #: without re-running anything.
    scan: Mapped[dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    #: The definition itself, so `warden tools diff` can show old against new.
    definition: Mapped[dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint("server", "tool", name="uq_tool_pins_server_tool"),
        Index("ix_tool_pins_status", "status"),
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "tool": self.tool,
            "name": f"{self.server}__{self.tool}",
            "sha256": self.sha256,
            "status": self.status,
            "reason": self.reason,
            "scan": self.scan,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "first_seen_at": self.first_seen_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


__all__ = ["ApiKey", "AuditEvent", "ToolPin"]
