"""Database tables.

Added phase by phase: `api_keys` in Phase 4, `audit_events` in 7, `tool_pins` in 8,
`approvals` in 9.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Index, String, Text
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


__all__ = ["ApiKey"]
