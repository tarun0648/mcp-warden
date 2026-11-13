"""Alembic environment.

The URL always comes from `warden.config.Settings` (so from `.env` or the environment), never
from alembic.ini: a database password must not live in a tracked file. SQLite needs
`render_as_batch` so an ALTER that SQLite cannot do is rewritten as a table rebuild.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from warden.config import Settings
from warden.db import models as _models  # noqa: F401  (import registers every table)
from warden.db.base import Base

config = context.config
if config.config_file_name is not None:
    # disable_existing_loggers defaults to True, which would switch off every logger that
    # already exists - including all of warden's. That matters beyond the test suite: a
    # process that runs `warden db upgrade` and then serves would lose its own logging.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def database_url() -> str:
    override = config.get_main_option("sqlalchemy.url", None)
    return override or Settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = database_url()
    engine = async_engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
