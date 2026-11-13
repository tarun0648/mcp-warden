"""Making `audit_events` append-only at the database level.

This is a privileged, one-off operation: it creates a NOLOGIN group role and grants it
`SELECT, INSERT` on the audit table and nothing else. It lives apart from the migration because
creating a role needs `CREATEROLE`, which the role that runs migrations usually does not and
should not have.

Run it once as a privileged role, then make the gateway's own login role a member:

    warden db harden --grant-to warden

After that, `UPDATE audit_events ...` and `DELETE FROM audit_events ...` are refused by Postgres
for the gateway, not merely absent from the code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from sqlalchemy import text

from warden.db.engine import Database
from warden.logging import get_logger

logger = get_logger(__name__)

GATEWAY_ROLE: Final = "warden_gateway"
AUDIT_TABLE: Final = "audit_events"


@dataclass(frozen=True, slots=True)
class HardenResult:
    """What `harden` did, so the CLI can report it and a test can assert it."""

    applied: bool
    role: str
    granted_to: str | None
    message: str


async def harden_audit_table(database: Database, *, grant_to: str | None = None) -> HardenResult:
    """Create the gateway role if needed and restrict it to SELECT + INSERT."""
    # Validate before any side effect: a bad grant target must not leave a half-applied state.
    grant_target = _quote_ident(grant_to) if grant_to else None
    if not database.is_postgres:
        return HardenResult(
            applied=False,
            role=GATEWAY_ROLE,
            granted_to=None,
            message=(
                "this database is not Postgres, so there are no roles to restrict; "
                "the audit log's append-only property rests on the hash chain alone"
            ),
        )

    async with database.engine.begin() as conn:
        await conn.execute(
            text(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{GATEWAY_ROLE}')
                    THEN
                        CREATE ROLE {GATEWAY_ROLE} NOLOGIN;
                    END IF;
                END $$;
                """
            )
        )
        # Order matters: revoke everything first, including from PUBLIC, then grant back
        # exactly the two privileges the gateway needs.
        await conn.execute(text(f"REVOKE ALL ON TABLE {AUDIT_TABLE} FROM PUBLIC"))
        await conn.execute(text(f"REVOKE ALL ON TABLE {AUDIT_TABLE} FROM {GATEWAY_ROLE}"))
        await conn.execute(text(f"GRANT SELECT, INSERT ON TABLE {AUDIT_TABLE} TO {GATEWAY_ROLE}"))
        await conn.execute(
            text(f"GRANT USAGE, SELECT ON SEQUENCE {AUDIT_TABLE}_id_seq TO {GATEWAY_ROLE}")
        )
        if grant_target:
            await conn.execute(text(f"GRANT {GATEWAY_ROLE} TO {grant_target}"))

    logger.warning(
        "audit table hardened",
        extra={"warden": {"role": GATEWAY_ROLE, "granted_to": grant_to}},
    )
    return HardenResult(
        applied=True,
        role=GATEWAY_ROLE,
        granted_to=grant_to,
        message=(
            f"{AUDIT_TABLE} now grants only SELECT and INSERT to {GATEWAY_ROLE}. "
            "A table owner still bypasses grants, so run the gateway as a non-owner member "
            "of that role."
        ),
    )


async def audit_privileges(database: Database, role: str) -> dict[str, bool]:
    """Which privileges `role` actually holds on the audit table, straight from Postgres."""
    if not database.is_postgres:
        return {}
    privileges = {}
    async with database.engine.connect() as conn:
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            result = await conn.execute(
                text("SELECT has_table_privilege(:role, :table, :privilege)"),
                {"role": role, "table": AUDIT_TABLE, "privilege": privilege},
            )
            privileges[privilege] = bool(result.scalar_one())
    return privileges


def _quote_ident(name: str) -> str:
    """Quote an identifier. Grant targets come from an operator's command line, not a request.

    Postgres cannot parameterise an identifier, so the only safe handling is to reject anything
    that is not a plain name.
    """
    if not name.replace("_", "").isalnum():
        raise ValueError(f"'{name}' is not a plain role name")
    return f'"{name}"'


__all__ = [
    "AUDIT_TABLE",
    "GATEWAY_ROLE",
    "HardenResult",
    "audit_privileges",
    "harden_audit_table",
]
