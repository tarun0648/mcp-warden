"""The `warden` command line.

Phase 3 provides `serve`, `tools` and `check-config`. Later phases add `keys`, `token`,
`audit`, `approvals` and the pin management commands.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from warden.config import (
    GatewayConfig,
    PoliciesConfig,
    ServersConfig,
    Settings,
    load_gateway_config,
    load_policies_config,
    load_servers_config,
)
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


def main() -> None:
    try:
        app()
    except ConfigError as exc:  # pragma: no cover - typer normally catches this first
        console.print(f"[red]configuration error:[/red] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
