"""The parts of the audit log that only Postgres can prove.

Two claims live here that SQLite cannot test: the append lock really is a cross-process
advisory lock, and the table really is append-only by grant rather than by convention.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from sqlalchemy import text

from tests.conftest import requires_postgres

pytestmark = pytest.mark.integration

ADMIN_URL = "postgresql+asyncpg://warden:warden_dev_password_change_me@localhost:5432/warden"


def database_url(name: str) -> str:
    return f"postgresql+asyncpg://warden:warden_dev_password_change_me@localhost:5432/{name}"


async def _run_outside_transaction(statement: str) -> None:
    """CREATE/DROP DATABASE cannot run inside a transaction."""
    from warden.db.engine import Database

    admin = Database(ADMIN_URL)
    try:
        async with admin.engine.connect() as conn:
            await conn.execution_options(isolation_level="AUTOCOMMIT")
            await conn.execute(text(statement))
    finally:
        await admin.dispose()


@pytest.fixture
async def pg_database() -> Any:
    """A Database on a throwaway Postgres database, with every table created.

    A whole database rather than a schema: `create_all` checks whether a table already exists
    by name, and the project's own `warden` database already has an `audit_events` table from
    `alembic upgrade head`, so a schema-scoped run quietly created nothing.
    """
    from warden.db.engine import Database

    name = f"warden_test_{uuid.uuid4().hex[:12]}"
    await _run_outside_transaction(f'CREATE DATABASE "{name}"')
    database = Database(database_url(name))
    await database.create_all()
    try:
        yield database
    finally:
        await database.dispose()
        await _run_outside_transaction(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def _db_name(database: Any) -> str:
    return str(database.url).rsplit("/", 1)[1]


def row_fields(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "request_id": uuid.uuid4().hex,
        "event": "finished",
        "principal_id": "alice",
        "auth_method": "api_key",
        "method": "tools/call",
        "tool": "files__read_file",
        "upstream": "files",
        "risk": "read",
        "args_redacted": {"path": "a.md"},
        "args_sha256": "a" * 64,
        "decision": "allow",
        "reason_code": "WARDEN_ALLOWED",
        "matched_rule": None,
        "stage_timings_ms": {"policy": 0.5},
        "result_bytes": 10,
        "result_sha256": None,
        "scan_flags": {},
    }
    base.update(overrides)
    return base


@requires_postgres
async def test_the_chain_verifies_on_postgres(pg_database: Any) -> None:
    from warden.audit.log import AuditLog

    audit = AuditLog(pg_database)
    assert pg_database.is_postgres, "this test must exercise the Postgres path"
    for _ in range(20):
        await audit.append(**row_fields())
    result = await audit.verify()
    assert result.ok, result.summary()
    assert result.rows_checked == 20


@requires_postgres
async def test_a_hundred_concurrent_appends_on_postgres_still_verify(
    pg_database: Any,
) -> None:
    """`pg_advisory_xact_lock` is what makes this hold across processes, not just tasks."""
    from warden.audit.log import AuditLog

    audit = AuditLog(pg_database)
    await asyncio.gather(*(audit.append(**row_fields()) for _ in range(100)))
    result = await audit.verify()
    assert result.ok, result.summary()
    assert result.rows_checked == 100


@requires_postgres
async def test_two_independent_writers_do_not_fork_the_chain(pg_database: Any) -> None:
    """Two AuditLog instances stand in for two gateway processes.

    Each has its own asyncio lock, so only the database-level advisory lock can keep them in
    step. If it did not, both would read the same head and the chain would fork - which
    `verify` reports as tampering, from two honest gateways.
    """
    from warden.audit.log import AuditLog

    first = AuditLog(pg_database)
    second = AuditLog(pg_database)
    await asyncio.gather(
        *(first.append(**row_fields(principal_id="one")) for _ in range(25)),
        *(second.append(**row_fields(principal_id="two")) for _ in range(25)),
    )
    result = await first.verify()
    assert result.ok, result.summary()
    assert result.rows_checked == 50


@requires_postgres
async def test_timestamps_round_trip_through_postgres_without_breaking_the_hash(
    pg_database: Any,
) -> None:
    """The hash covers `ts`, so a lost microsecond would look like tampering."""
    from datetime import UTC, datetime

    from warden.audit.log import AuditLog

    audit = AuditLog(pg_database)
    await audit.append(ts=datetime(2026, 11, 13, 12, 0, 0, 123456, tzinfo=UTC), **row_fields())
    assert (await audit.verify()).ok


@requires_postgres
async def test_the_audit_table_is_append_only_for_a_non_owner_member(
    pg_database: Any,
) -> None:
    """`warden db harden` is what turns the convention into a rule.

    The gateway's own connection in these tests owns the table, and a table owner bypasses
    grants. So this test creates a separate login role, makes it a member of the gateway group
    role, and checks what Postgres actually permits it to do.
    """
    from sqlalchemy.exc import ProgrammingError

    from warden.audit.harden import audit_privileges, harden_audit_table
    from warden.db.engine import Database

    outcome = await harden_audit_table(pg_database)
    assert outcome.applied

    login_role = f"warden_probe_{uuid.uuid4().hex[:8]}"
    password = "probe_password_not_a_real_secret"

    async with pg_database.engine.begin() as conn:
        await conn.execute(text(f"CREATE ROLE {login_role} LOGIN PASSWORD '{password}'"))
        await conn.execute(text(f"GRANT warden_gateway TO {login_role}"))
        await conn.execute(
            text(f'GRANT CONNECT ON DATABASE "{_db_name(pg_database)}" TO {login_role}')
        )
        await conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {login_role}"))

    privileges = await audit_privileges(pg_database, login_role)
    assert privileges["SELECT"] is True
    assert privileges["INSERT"] is True
    assert privileges["UPDATE"] is False, "the gateway must not be able to edit a row"
    assert privileges["DELETE"] is False, "the gateway must not be able to remove a row"
    assert privileges["TRUNCATE"] is False

    # And prove it by trying, as that role, over a real connection.
    probe = Database(
        f"postgresql+asyncpg://{login_role}:{password}@localhost:5432/{_db_name(pg_database)}"
    )
    try:
        async with probe.engine.begin() as conn:
            await conn.execute(text("SELECT count(*) FROM audit_events"))
        async with probe.engine.begin() as conn:
            with pytest.raises(ProgrammingError, match="permission denied"):
                await conn.execute(text("UPDATE audit_events SET decision = 'allow'"))
        async with probe.engine.begin() as conn:
            with pytest.raises(ProgrammingError, match="permission denied"):
                await conn.execute(text("DELETE FROM audit_events"))
    finally:
        await probe.dispose()
        async with pg_database.engine.begin() as conn:
            await conn.execute(text(f"REVOKE ALL ON SCHEMA public FROM {login_role}"))
            await conn.execute(
                text(f'REVOKE ALL ON DATABASE "{_db_name(pg_database)}" FROM {login_role}')
            )
            await conn.execute(text(f"REVOKE warden_gateway FROM {login_role}"))
            # Every grant counts as a dependency, so the role cannot be dropped until all of
            # them are gone - including the database-level CONNECT, which lives in a shared
            # catalog and so outlives the throwaway database.
            await conn.execute(text(f"DROP ROLE IF EXISTS {login_role}"))


@requires_postgres
async def test_harden_is_a_no_op_on_sqlite(tmp_path: Any) -> None:
    """And says so, rather than pretending the table is protected."""
    from warden.audit.harden import harden_audit_table
    from warden.db.engine import Database

    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'x.sqlite3'}")
    try:
        await database.create_all()
        outcome = await harden_audit_table(database)
        assert outcome.applied is False
        assert "not Postgres" in outcome.message
        assert await audit_privileges_is_empty(database)
    finally:
        await database.dispose()


async def audit_privileges_is_empty(database: Any) -> bool:
    from warden.audit.harden import audit_privileges

    return await audit_privileges(database, "anyone") == {}


@requires_postgres
async def test_harden_rejects_a_role_name_that_is_not_a_plain_identifier(
    pg_database: Any,
) -> None:
    """The grant target comes from an operator's command line; Postgres cannot bind it."""
    from warden.audit.harden import harden_audit_table

    with pytest.raises(ValueError, match="plain role name"):
        await harden_audit_table(pg_database, grant_to='warden"; DROP TABLE audit_events; --')
