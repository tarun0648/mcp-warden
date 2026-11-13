"""Engine and session management.

`Database` is the only place that knows the dialect. Everything else asks it questions
(`is_postgres`, `advisory_lock`) instead of inspecting URLs.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from warden.db.base import Base
from warden.logging import get_logger

logger = get_logger(__name__)

#: One 64-bit key per lock we take. Postgres advisory locks are global to the database, so a
#: fixed, documented key stops two features from colliding.
AUDIT_CHAIN_LOCK_KEY = 0x7761_7264_656E_0001


class Database:
    """An async engine plus a session factory, with the dialect differences in one place."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        self.url = url
        if url.startswith("sqlite"):
            _ensure_sqlite_directory(url)
        self.engine: AsyncEngine = create_async_engine(
            url,
            echo=echo,
            pool_pre_ping=True,
            # SQLite's default isolation makes concurrent writers fail with "database is
            # locked"; WAL plus a busy timeout is set per connection in `_prepare_sqlite`.
            connect_args={"timeout": 30} if url.startswith("sqlite") else {},
        )
        self.session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False
        )

    @property
    def is_postgres(self) -> bool:
        return self.engine.dialect.name == "postgresql"

    @property
    def is_sqlite(self) -> bool:
        return self.engine.dialect.name == "sqlite"

    async def prepare(self) -> None:
        """Apply per-database settings that must be set on every connection."""
        if self.is_sqlite:
            async with self.engine.begin() as conn:
                await conn.execute(text("PRAGMA journal_mode=WAL"))
                await conn.execute(text("PRAGMA busy_timeout=30000"))
                await conn.execute(text("PRAGMA foreign_keys=ON"))

    async def create_all(self) -> None:
        """Create every table from the model metadata.

        Used by tests and by a first local run. Deployments use Alembic; a drift test asserts
        that the Alembic head and this metadata agree.
        """
        await self.prepare()
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """A session that commits on success and rolls back on any exception."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    @contextlib.asynccontextmanager
    async def transaction_with_lock(self, key: int) -> AsyncIterator[AsyncSession]:
        """A session holding a serialising lock for `key` until the transaction ends.

        On Postgres this is `pg_advisory_xact_lock`, which serialises across every gateway
        process sharing the database. On SQLite there is nothing to take: writes are already
        serialised by the file lock, and a single-file database is single-node by definition.
        The caller is told which it got through `is_postgres`, so a test can assert that the
        Postgres path is the one exercised in CI.
        """
        async with self.session_factory() as session:
            try:
                if self.is_postgres:
                    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def dispose(self) -> None:
        await self.engine.dispose()


def _ensure_sqlite_directory(url: str) -> None:
    """Create the parent directory of a SQLite file so the first connection does not fail."""
    _, _, path = url.partition(":///")
    if not path or path == ":memory:":
        return
    Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)


__all__ = ["AUDIT_CHAIN_LOCK_KEY", "Database"]
