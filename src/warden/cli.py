"""The `warden` command line.

Phase 3 provides `serve`, `tools` and `check-config`. Later phases add `keys`, `token`,
`audit`, `approvals` and the pin management commands.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from warden.auth.api_keys import ApiKeyStore
from warden.auth.jwt_keys import JwtKeyStore, KeyStoreError
from warden.auth.tokens import TokenConfig, TokenService
from warden.config import (
    GatewayConfig,
    PoliciesConfig,
    ServersConfig,
    Settings,
    load_gateway_config,
    load_policies_config,
    load_servers_config,
)
from warden.db.engine import Database
from warden.errors import ConfigError
from warden.logging import configure_logging

app = typer.Typer(
    name="warden",
    help="mcp-warden: a security gateway for the Model Context Protocol.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _settings() -> Settings:
    return Settings()


@app.command()
def serve(
    host: Annotated[str | None, typer.Option(help="Host to bind. Defaults to WARDEN_HOST.")] = None,
    port: Annotated[int | None, typer.Option(help="Port to bind. Defaults to WARDEN_PORT.")] = None,
    wait_upstreams: Annotated[
        float, typer.Option(help="Seconds to wait for upstreams before serving.")
    ] = 5.0,
) -> None:
    """Run the gateway."""
    from warden.main import create_app

    settings = _settings()
    configure_logging(settings.log_level)
    try:
        application = create_app(settings, upstream_wait_seconds=wait_upstreams)
    except ConfigError as exc:
        console.print(f"[red]configuration error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    uvicorn.run(
        application,
        host=host or settings.warden_host,
        port=port or settings.warden_port,
        log_config=None,
    )


@app.command(name="check-config")
def check_config() -> None:
    """Validate gateway.yaml, servers.yaml and policies.yaml, then report what they say."""
    settings = _settings()
    problems: list[str] = []
    gateway: GatewayConfig | None = None
    servers: ServersConfig | None = None
    policies: PoliciesConfig | None = None

    try:
        gateway = load_gateway_config(settings.gateway_yaml)
    except ConfigError as exc:
        problems.append(str(exc))
    try:
        servers = load_servers_config(settings.servers_yaml)
    except ConfigError as exc:
        problems.append(str(exc))
    try:
        policies = load_policies_config(settings.policies_yaml)
    except ConfigError as exc:
        problems.append(str(exc))

    if problems or gateway is None or servers is None or policies is None:
        for problem in problems:
            console.print(f"[red]x[/red] {problem}")
        raise typer.Exit(code=2)

    console.print("[green]ok[/green] all three configuration files are valid")
    enabled = ", ".join(u.name for u in servers.enabled) or "none enabled"
    console.print(f"  upstreams: {len(servers.upstreams)} ({enabled})")
    console.print(f"  roles:     {', '.join(sorted(policies.roles)) or 'none'}")
    console.print(f"  limits:    max result {gateway.limits.max_result_bytes} bytes")


@app.command()
def tools(
    wait: Annotated[float, typer.Option(help="Seconds to wait for upstreams to connect.")] = 15.0,
) -> None:
    """Connect to every enabled upstream and print the aggregated tool list."""
    settings = _settings()
    configure_logging("WARNING")
    try:
        gateway = load_gateway_config(settings.gateway_yaml)
        servers = load_servers_config(settings.servers_yaml)
    except ConfigError as exc:
        console.print(f"[red]configuration error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    asyncio.run(_print_tools(gateway, servers, wait))


async def _print_tools(gateway: GatewayConfig, servers: ServersConfig, wait: float) -> None:
    from warden.main import build_upstream_manager
    from warden.proxy.registry import ToolRegistry

    manager = build_upstream_manager(gateway, servers)
    registry = ToolRegistry()
    manager.on_tools_changed = registry.replace
    await manager.start(wait_seconds=wait)
    try:
        table = Table(title="tools available through the gateway")
        table.add_column("tool")
        table.add_column("upstream")
        table.add_column("risk")
        table.add_column("description", overflow="fold", max_width=60)
        for tool in registry:
            upstream = servers.by_name(tool.upstream)
            risk = upstream.risk_for(tool.upstream_tool) if upstream else "?"
            table.add_row(
                tool.name,
                tool.upstream,
                str(risk),
                _one_line(tool.definition.description or ""),
            )
        console.print(table)

        health = Table(title="upstream health")
        health.add_column("upstream")
        health.add_column("state")
        health.add_column("tools")
        health.add_column("last error", overflow="fold", max_width=50)
        for name, status in manager.health().items():
            health.add_row(
                name, str(status.state), str(status.tool_count), status.last_error or "-"
            )
        console.print(health)

        if registry.rejected:
            console.print("[yellow]rejected upstream tools:[/yellow]")
            for key, why in registry.rejected.items():
                console.print(f"  {key}: {why}")
    finally:
        await manager.stop()


def _one_line(text: str) -> str:
    """Collapse a description to one printable line, with invisible characters made visible.

    An upstream description is untrusted data. Printing it raw lets a poisoned tool hide
    content from whoever runs this command, which is exactly the attack.
    """
    cleaned = []
    for char in text:
        if char in "\r\n\t":
            cleaned.append(" ")
        elif char.isprintable():
            cleaned.append(char)
        else:
            cleaned.append(f"<U+{ord(char):04X}>")
    collapsed = " ".join("".join(cleaned).split())
    return collapsed[:300] + ("..." if len(collapsed) > 300 else "")


# ----------------------------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------------------------

db_app = typer.Typer(help="Database schema management.", no_args_is_help=True)
app.add_typer(db_app, name="db")


def _alembic_config() -> Any:
    """Alembic's config, pointed at this repo's migrations.

    `stdout` is passed explicitly because `alembic.config.Config` binds `sys.stdout` as a
    *default argument*, so it captures whatever stdout was at import time - which is the wrong
    stream once anything has redirected it, and a closed one under a CLI test runner.
    """
    from alembic.config import Config

    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"), stdout=sys.stdout)
    config.set_main_option("script_location", str(root / "migrations"))
    return config


@db_app.command("upgrade")
def db_upgrade(
    revision: Annotated[str, typer.Argument(help="Target revision.")] = "head",
) -> None:
    """Apply migrations up to `revision`."""
    from alembic import command

    command.upgrade(_alembic_config(), revision)
    console.print(f"[green]ok[/green] database is at {revision}")


@db_app.command("downgrade")
def db_downgrade(
    revision: Annotated[str, typer.Argument(help="Target revision.")],
) -> None:
    """Roll migrations back to `revision`."""
    from alembic import command

    command.downgrade(_alembic_config(), revision)
    console.print(f"[green]ok[/green] database is at {revision}")


@db_app.command("current")
def db_current() -> None:
    """Print the revision the database is on."""
    from alembic import command

    command.current(_alembic_config(), verbose=True)


# ----------------------------------------------------------------------------------------------
# Credentials
# ----------------------------------------------------------------------------------------------

keys_app = typer.Typer(help="API keys and JWT signing keys.", no_args_is_help=True)
app.add_typer(keys_app, name="keys")


def _database() -> Database:
    return Database(_settings().database_url)


@keys_app.command("create")
def keys_create(
    user: Annotated[str, typer.Option(help="The user id the key authenticates as.")],
    roles: Annotated[str, typer.Option(help="Comma-separated roles, e.g. reader,editor.")],
    label: Annotated[str | None, typer.Option(help="A note about where this key is used.")] = None,
) -> None:
    """Mint an API key. The secret is printed once and cannot be recovered."""
    role_list = [role.strip() for role in roles.split(",") if role.strip()]
    if not role_list:
        console.print("[red]error:[/red] give at least one role")
        raise typer.Exit(code=2)
    generated = asyncio.run(_create_key(user, role_list, label))
    console.print("[green]key created.[/green] This is the only time it is shown:")
    console.print(f"\n  [bold]{generated.secret}[/bold]\n", soft_wrap=True)
    console.print(f"  prefix: {generated.prefix}   user: {user}   roles: {', '.join(role_list)}")
    console.print("Store it in a password manager or a secret store. Never commit it.")


async def _create_key(user: str, roles: list[str], label: str | None) -> Any:
    database = _database()
    try:
        return await ApiKeyStore(database).create(user, roles, label=label)
    finally:
        await database.dispose()


@keys_app.command("list")
def keys_list(
    active_only: Annotated[bool, typer.Option(help="Hide revoked keys.")] = False,
) -> None:
    """List API keys. Never prints a secret or a hash."""
    rows = asyncio.run(_list_keys(not active_only))
    table = Table(title="api keys")
    for column in ("prefix", "user", "roles", "label", "created", "last used", "revoked"):
        table.add_column(column)
    for row in rows:
        table.add_row(
            row["prefix"],
            row["user_id"],
            ", ".join(row["roles"]),
            row["label"] or "-",
            row["created_at"][:19],
            (row["last_used_at"] or "-")[:19],
            (row["revoked_at"] or "-")[:19],
        )
    console.print(table)


async def _list_keys(include_revoked: bool) -> list[dict[str, Any]]:
    database = _database()
    try:
        keys = await ApiKeyStore(database).list_keys(include_revoked=include_revoked)
        return [key.as_dict() for key in keys]
    finally:
        await database.dispose()


@keys_app.command("revoke")
def keys_revoke(
    prefix: Annotated[str, typer.Argument(help="The key prefix shown by `warden keys list`.")],
) -> None:
    """Revoke every key with this prefix. Takes effect on the next request."""
    count = asyncio.run(_revoke_key(prefix))
    if count == 0:
        console.print(f"[yellow]no active key with prefix {prefix}[/yellow]")
        raise typer.Exit(code=1)
    console.print(f"[green]ok[/green] revoked {count} key(s) with prefix {prefix}")


async def _revoke_key(prefix: str) -> int:
    database = _database()
    try:
        return await ApiKeyStore(database).revoke(prefix)
    finally:
        await database.dispose()


@keys_app.command("init-jwt")
def keys_init_jwt() -> None:
    """Create the ES256 signing key, if there is not one already."""
    settings = _settings()
    kid = JwtKeyStore(settings.jwt_key_dir).initialise()
    console.print(f"[green]ok[/green] active signing key: {kid}")
    console.print(f"  private keys live in {settings.jwt_key_dir} (gitignored, mode 0600)")


@keys_app.command("rotate-jwt")
def keys_rotate_jwt() -> None:
    """Add a new signing key, keeping the previous one able to verify."""
    settings = _settings()
    store = JwtKeyStore(settings.jwt_key_dir)
    kid = store.rotate()
    state = store.read_state()
    console.print(f"[green]ok[/green] new signing key: {kid}")
    console.print(f"  active (verify + sign): {', '.join(state.active)}")
    console.print(f"  retired (rejected):     {', '.join(state.retired) or 'none'}")


@keys_app.command("jwks")
def keys_jwks() -> None:
    """Print the public JWKS document the gateway serves."""
    settings = _settings()
    console.print_json(data=JwtKeyStore(settings.jwt_key_dir).jwks())


token_app = typer.Typer(help="Development token issuing.", no_args_is_help=True)
app.add_typer(token_app, name="token")


@token_app.command("create")
def token_create(
    user: Annotated[str, typer.Option(help="The subject the token authenticates as.")],
    roles: Annotated[str, typer.Option(help="Comma-separated roles.")],
    ttl: Annotated[int, typer.Option(help="Lifetime in seconds.")] = 900,
) -> None:
    """Issue a short-lived ES256 token. A real deployment uses an external OAuth server."""
    settings = _settings()
    role_list = [role.strip() for role in roles.split(",") if role.strip()]
    if not role_list:
        console.print("[red]error:[/red] give at least one role")
        raise typer.Exit(code=2)
    service = TokenService(
        JwtKeyStore(settings.jwt_key_dir),
        TokenConfig(
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            default_ttl_seconds=settings.jwt_default_ttl_seconds,
            clock_skew_seconds=settings.jwt_clock_skew_seconds,
        ),
    )
    try:
        issued = service.issue(user, role_list, ttl_seconds=ttl)
    except KeyStoreError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    # soft_wrap, because rich otherwise breaks a long token across lines and what the
    # operator copies is then not a token.
    console.print(issued.token, soft_wrap=True)
    console.print(
        f"[dim]jti={issued.jti} expires_at={issued.expires_at} aud={settings.jwt_audience}[/dim]"
    )


@db_app.command("harden")
def db_harden(
    grant_to: Annotated[
        str | None,
        typer.Option(help="Also make this login role a member of the gateway role."),
    ] = None,
) -> None:
    """Make audit_events append-only: SELECT + INSERT only, no UPDATE or DELETE.

    Needs a role with CREATEROLE, so it is separate from `warden db upgrade`.
    """
    from warden.audit.harden import harden_audit_table

    async def run() -> Any:
        database = _database()
        try:
            return await harden_audit_table(database, grant_to=grant_to)
        finally:
            await database.dispose()

    outcome = asyncio.run(run())
    style = "green" if outcome.applied else "yellow"
    console.print(f"[{style}]{'ok' if outcome.applied else 'skipped'}[/{style}] {outcome.message}")


# ----------------------------------------------------------------------------------------------
# Audit log
# ----------------------------------------------------------------------------------------------

audit_app = typer.Typer(help="The tamper-evident audit log.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")


@audit_app.command("verify")
def audit_verify() -> None:
    """Walk the hash chain and report the first row that does not add up."""
    from warden.audit.log import AuditLog

    async def run() -> Any:
        database = _database()
        try:
            return await AuditLog(database).verify()
        finally:
            await database.dispose()

    result = asyncio.run(run())
    if result.ok:
        console.print(f"[green]OK[/green] {result.rows_checked} rows verified")
        console.print(f"  head hash: {result.head_hash}")
        console.print(
            "  Pin that hash somewhere the gateway cannot write to detect a wholesale rebuild."
        )
        return
    console.print(f"[red]BROKEN[/red] after {result.rows_checked} verified rows")
    console.print(f"  {result.first_break}")
    raise typer.Exit(code=1)


@audit_app.command("tail")
def audit_tail(
    limit: Annotated[int, typer.Option(help="How many rows to show.")] = 20,
    user: Annotated[str | None, typer.Option(help="Filter by principal id.")] = None,
    tool: Annotated[str | None, typer.Option(help="Filter by namespaced tool name.")] = None,
    decision: Annotated[str | None, typer.Option(help="allow | deny | pending.")] = None,
    request_id: Annotated[str | None, typer.Option(help="Show one request's rows.")] = None,
) -> None:
    """Show the most recent audit rows."""
    from warden.audit.log import AuditFilters, AuditLog

    async def run() -> Any:
        database = _database()
        try:
            return await AuditLog(database).query(
                AuditFilters(
                    principal_id=user, tool=tool, decision=decision, request_id=request_id
                ),
                limit=limit,
            )
        finally:
            await database.dispose()

    page = asyncio.run(run())
    table = Table(title="audit events (newest first)")
    for column in ("id", "ts", "event", "user", "tool", "decision", "reason", "rule"):
        table.add_column(column, overflow="fold")
    for row in page.rows:
        table.add_row(
            str(row["id"]),
            row["ts"][:19],
            row["event"],
            row["principal_id"] or "-",
            row["tool"] or "-",
            row["decision"],
            row["reason_code"],
            row["matched_rule"] or "-",
        )
    console.print(table)
    if page.next_cursor is not None:
        console.print(f"[dim]more rows available; next cursor {page.next_cursor}[/dim]")


@audit_app.command("privileges")
def audit_privileges_command(
    role: Annotated[str, typer.Argument(help="The role to inspect.")],
) -> None:
    """Print the privileges a role actually holds on audit_events, straight from Postgres."""
    from warden.audit.harden import audit_privileges

    async def run() -> Any:
        database = _database()
        try:
            return await audit_privileges(database, role)
        finally:
            await database.dispose()

    privileges = asyncio.run(run())
    if not privileges:
        console.print("[yellow]not Postgres: there are no table privileges to report[/yellow]")
        return
    table = Table(title=f"audit_events privileges for {role}")
    table.add_column("privilege")
    table.add_column("granted")
    for name, granted in privileges.items():
        expected_absent = name in ("UPDATE", "DELETE", "TRUNCATE")
        mark = "yes" if granted else "no"
        style = "red" if (granted and expected_absent) else "green"
        table.add_row(name, f"[{style}]{mark}[/{style}]")
    console.print(table)


def main() -> None:
    try:
        app()
    except ConfigError as exc:  # pragma: no cover - typer normally catches this first
        console.print(f"[red]configuration error:[/red] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
