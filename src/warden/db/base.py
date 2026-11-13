"""SQLAlchemy declarative base and shared column types.

The same models run on Postgres (production) and SQLite (unit tests, and a single-file local
run). Dialect-specific behaviour is confined to `warden.db.engine`, and anything a dialect
cannot do - an advisory lock, a role grant - is behind an explicit capability check rather than
an exception handler.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import JSON

#: Explicit constraint naming, so an Alembic autogenerate diff is stable and a migration can
#: drop a constraint by name on both dialects.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


#: JSONB on Postgres (indexable, typed) and JSON on everything else.
JsonColumn = JSON().with_variant(JSONB(), "postgresql")


class UtcDateTime(TypeDecorator[datetime]):
    """A timezone-aware UTC timestamp that round-trips identically on SQLite and Postgres.

    SQLite has no timezone-aware type, so a naive value comes back from the driver. Rather than
    let a naive datetime escape into comparisons and audit rows, this normalises in both
    directions: aware values are converted to UTC going in, and naive values are labelled UTC
    coming out.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("refusing to store a naive datetime; pass an aware UTC value")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def utcnow() -> datetime:
    """The current time, always timezone-aware."""
    return datetime.now(UTC)


__all__ = ["Base", "JsonColumn", "UtcDateTime", "utcnow"]
