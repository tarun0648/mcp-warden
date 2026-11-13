"""Two things that need a real service or a real migration run."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import inspect

from tests.conftest import requires_redis

pytestmark = pytest.mark.integration


def test_alembic_head_matches_the_model_metadata(tmp_path: Path) -> None:
    """Migrations and models must not drift.

    Tests create tables from the metadata because it is fast; deployments run Alembic. If the
    two ever disagree, a migration-created database would be missing something the code expects.

    Synchronous on purpose: Alembic's env.py calls `asyncio.run`, which cannot run inside an
    already-running loop, so the async half goes through a worker-thread helper.
    """
    from alembic import command
    from alembic.config import Config

    from tests.helpers import run_async
    from warden.db.base import Base
    from warden.db.engine import Database

    repo_root = Path(__file__).resolve().parents[2]
    migrated_url = f"sqlite+aiosqlite:///{tmp_path / 'migrated.sqlite3'}"
    config = Config(str(repo_root / "alembic.ini"))
    config.set_main_option("script_location", str(repo_root / "migrations"))
    config.set_main_option("sqlalchemy.url", migrated_url)
    command.upgrade(config, "head")

    async def reflect() -> dict[str, set[str]]:
        database = Database(migrated_url)
        try:
            async with database.engine.connect() as conn:
                tables = await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
                shape: dict[str, set[str]] = {}
                for table in sorted(tables - {"alembic_version"}):
                    columns = await conn.run_sync(
                        lambda c, t=table: {col["name"] for col in inspect(c).get_columns(t)}
                    )
                    shape[table] = columns
                return shape
        finally:
            await database.dispose()

    migrated_shape = run_async(reflect)

    expected = {name: set(table.columns.keys()) for name, table in Base.metadata.tables.items()}
    assert set(migrated_shape) == set(expected), (
        "alembic head and the model metadata describe different tables"
    )
    for table, columns in migrated_shape.items():
        assert columns == expected[table], (
            f"table '{table}' differs between the migration and the model"
        )


@requires_redis
async def test_token_revocation_against_real_redis(tmp_path: Path) -> None:
    """The revocation list is the one piece of auth that needs Redis, so it gets a real test."""
    import redis.asyncio as aioredis

    from warden.auth.jwt_keys import JwtKeyStore
    from warden.auth.tokens import (
        InvalidToken,
        RedisRevocationStore,
        TokenConfig,
        TokenService,
    )

    keys = JwtKeyStore(tmp_path / "keys")
    keys.initialise()
    client: aioredis.Redis = aioredis.from_url("redis://localhost:6379/15")
    try:
        await client.flushdb()
        service = TokenService(
            keys,
            TokenConfig(issuer="http://localhost:8080", audience="http://localhost:8080/mcp"),
            RedisRevocationStore(client),
        )
        issued = service.issue("alice", ["editor"], ttl_seconds=60)
        assert (await service.verify(issued.token)).user_id == "alice"
        await service.revoke(issued.token)
        with pytest.raises(InvalidToken, match="revoked"):
            await service.verify(issued.token)
        ttl = await client.ttl(f"warden:jwt:revoked:{issued.jti}")
        assert 0 < ttl <= 60
    finally:
        await client.flushdb()
        await client.aclose()
