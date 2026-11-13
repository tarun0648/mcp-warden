"""The gateway's HTTP application factory.

One Starlette app serves everything: `/mcp` (Streamable HTTP, the MCP endpoint clients talk to),
`/healthz` and `/readyz`, and from later phases the JWKS document, the admin API and the
approval UI. `create_app` wires the upstream manager, the tool registry and the request
pipeline together and hands their lifetimes to the ASGI lifespan.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from warden.auth.api_keys import ApiKeyStore
from warden.auth.jwt_keys import JwtKeyStore, KeyStoreError
from warden.auth.middleware import Authenticator, AuthMiddleware, principal_from_request
from warden.auth.stage import Authenticate
from warden.auth.tokens import (
    NullRevocationStore,
    RedisRevocationStore,
    RevocationStore,
    TokenConfig,
    TokenService,
)
from warden.config import (
    GatewayConfig,
    ServersConfig,
    Settings,
    load_gateway_config,
    load_servers_config,
)
from warden.db.engine import Database
from warden.health import Readiness, postgres_check, redis_check
from warden.logging import configure_logging, get_logger, request_id_var
from warden.pipeline import Pipeline
from warden.proxy.registry import ToolRegistry
from warden.proxy.server import GatewayDeps, build_mcp_server
from warden.proxy.stages import ForwardToUpstream, ResolveTool
from warden.upstream.manager import UpstreamManager

logger = get_logger(__name__)

REQUEST_ID_HEADER = "x-request-id"
MCP_PATH = "/mcp"
JWKS_PATH = "/.well-known/jwks.json"
PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource"
#: Paths that require a credential. Public by design: the health checks (a load balancer has no
#: credential) and the two well-known documents (a client must read them to get one).
PROTECTED_PREFIXES = (MCP_PATH, "/admin")


def default_readiness(settings: Settings) -> Readiness:
    """Readiness over the real Postgres and Redis named in the settings."""
    return Readiness(
        {
            "postgres": postgres_check(settings.database_url),
            "redis": redis_check(settings.redis_url),
        }
    )


async def healthz(_: Request) -> Response:
    """Liveness: 200 whenever the process is running and can serve a request."""
    return JSONResponse({"status": "ok"})


def make_readyz(readiness: Readiness) -> Callable[[Request], Awaitable[Response]]:
    """Readiness: 200 only when every dependency answers; 503 naming what is down."""

    async def readyz(_: Request) -> Response:
        report = await readiness.check()
        body: dict[str, object] = {
            "status": "ready" if report.ready else "not_ready",
            "checks": report.checks,
        }
        if not report.ready:
            down = [name for name, status in report.checks.items() if status != "ok"]
            body["unavailable"] = down
            logger.warning("readiness check failed", extra={"warden": {"unavailable": down}})
        return JSONResponse(body, status_code=200 if report.ready else 503)

    return readyz


class RequestIdMiddleware:
    """Give every request an id, bind it to the log context and echo it back in a header."""

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:  # type: ignore[type-arg]
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = _header(scope, REQUEST_ID_HEADER)
        request_id = _safe_request_id(incoming) or uuid.uuid4().hex
        token = request_id_var.set(request_id)

        async def send_with_header(message: dict) -> None:  # type: ignore[type-arg]
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((REQUEST_ID_HEADER.encode(), request_id.encode()))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_header)
        finally:
            request_id_var.reset(token)


def _header(scope: dict, name: str) -> str | None:  # type: ignore[type-arg]
    wanted = name.lower().encode()
    for key, value in scope.get("headers", []):
        if bytes(key).lower() == wanted:
            return bytes(value).decode("latin-1")
    return None


def _safe_request_id(value: str | None) -> str | None:
    """Accept a client-supplied request id only if it cannot pollute a log line."""
    if value is None:
        return None
    candidate = value.strip()
    if 1 <= len(candidate) <= 64 and all(ch.isalnum() or ch in "-_" for ch in candidate):
        return candidate
    return None


def make_jwks(keys: JwtKeyStore) -> Callable[[Request], Awaitable[Response]]:
    """Serve the public half of the signing keys so a client can verify a token itself."""

    async def jwks(_: Request) -> Response:
        try:
            document = keys.jwks()
        except KeyStoreError as exc:
            logger.warning(
                "jwks requested but no keys exist", extra={"warden": {"error": str(exc)}}
            )
            return JSONResponse({"keys": []}, status_code=503)
        return JSONResponse(document, headers={"Cache-Control": "public, max-age=300"})

    return jwks


def make_protected_resource_metadata(
    settings: Settings,
) -> Callable[[Request], Awaitable[Response]]:
    """OAuth 2.0 protected-resource metadata, as the MCP authorization spec expects.

    The dev issuer is this gateway itself (`warden token create`). A real deployment points
    `authorization_servers` at an external OAuth 2.1 server and stops issuing its own tokens;
    the verification path does not change. See docs/threat-model.md.
    """

    async def metadata(_: Request) -> Response:
        return JSONResponse(
            {
                "resource": settings.warden_resource_url,
                "authorization_servers": [settings.jwt_issuer],
                "bearer_methods_supported": ["header"],
                "jwks_uri": f"{settings.jwt_issuer.rstrip('/')}{JWKS_PATH}",
                "scopes_supported": [],
                "resource_documentation": "https://github.com/your-handle/mcp-warden",
            },
            headers={"Cache-Control": "public, max-age=300"},
        )

    return metadata


def build_revocation_store(settings: Settings) -> RevocationStore:
    """Redis-backed revocation when a Redis URL is configured, else an explicit no-op."""
    if not settings.redis_url:
        logger.warning("no redis url configured; token revocation will not work")
        return NullRevocationStore()
    import redis.asyncio as aioredis

    return RedisRevocationStore(aioredis.from_url(settings.redis_url))


def build_upstream_manager(
    gateway_config: GatewayConfig, servers_config: ServersConfig
) -> UpstreamManager:
    """An upstream manager configured from the gateway and servers files."""
    return UpstreamManager(
        servers_config,
        connect_timeout=gateway_config.upstream_connect_timeout_seconds,
        health_interval=gateway_config.upstream_health_interval_seconds,
        refresh_interval=gateway_config.tools_refresh_seconds,
    )


def build_pipeline_factory(
    registry: ToolRegistry, servers_config: ServersConfig, upstreams: UpstreamManager
) -> Callable[[], Pipeline]:
    """The pipeline, in the one order that is the security contract.

    Phase 4: authenticate, resolve, forward. Later phases insert DefinitionIntegrity, Policy,
    RateLimit and ArgumentDLP and Approval before `forward`, and OutputScan after it.
    """
    authenticate = Authenticate()
    resolve = ResolveTool(registry, servers_config)
    forward = ForwardToUpstream(upstreams)

    def factory() -> Pipeline:
        return Pipeline([authenticate, resolve, forward])

    return factory


def create_app(
    settings: Settings,
    *,
    readiness: Readiness | None = None,
    gateway_config: GatewayConfig | None = None,
    servers_config: ServersConfig | None = None,
    upstreams: UpstreamManager | None = None,
    database: Database | None = None,
    revocations: RevocationStore | None = None,
    mount_mcp: bool = True,
    upstream_wait_seconds: float = 0.0,
) -> Starlette:
    """Build the Starlette application.

    `mount_mcp=False` builds only the health endpoints, which is what the health unit tests
    want: mounting MCP would start the upstream subprocesses.
    """
    configure_logging(settings.log_level)
    checks = readiness if readiness is not None else default_readiness(settings)
    routes: list[Route] = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", make_readyz(checks), methods=["GET"]),
    ]

    gateway = (
        gateway_config if gateway_config is not None else load_gateway_config(settings.gateway_yaml)
    )
    servers = (
        servers_config if servers_config is not None else load_servers_config(settings.servers_yaml)
    )
    registry = ToolRegistry()
    manager = upstreams if upstreams is not None else build_upstream_manager(gateway, servers)
    manager.on_tools_changed = registry.replace

    db = database if database is not None else Database(settings.database_url)
    jwt_keys = JwtKeyStore(settings.jwt_key_dir)
    token_service = TokenService(
        jwt_keys,
        TokenConfig(
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            default_ttl_seconds=settings.jwt_default_ttl_seconds,
            clock_skew_seconds=settings.jwt_clock_skew_seconds,
        ),
        revocations if revocations is not None else build_revocation_store(settings),
    )
    authenticator = Authenticator(api_keys=ApiKeyStore(db), tokens=token_service)

    routes.append(Route(JWKS_PATH, make_jwks(jwt_keys), methods=["GET"]))
    routes.append(
        Route(PROTECTED_RESOURCE_PATH, make_protected_resource_metadata(settings), methods=["GET"])
    )

    mcp_server: Server[object] | None = None
    session_manager: StreamableHTTPSessionManager | None = None

    if mount_mcp:
        deps = GatewayDeps(
            settings_name="mcp-warden",
            gateway_config=gateway,
            servers_config=servers,
            registry=registry,
            upstreams=manager,
            pipeline_factory=build_pipeline_factory(registry, servers, manager),
            principal_resolver=lambda ctx: principal_from_request(ctx.request),
        )
        mcp_server = build_mcp_server(deps)
        session_manager = StreamableHTTPSessionManager(
            app=mcp_server,
            json_response=False,
            stateless=False,
            security_settings=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=settings.allowed_hosts,
                allowed_origins=settings.allowed_origins,
            ),
        )
        routes.append(Route(MCP_PATH, endpoint=StreamableHTTPASGIApp(session_manager)))

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        # Published so operational tooling (and tests) can schedule work on the loop that owns
        # the upstream connections, rather than touching them from another loop.
        app.state.loop = asyncio.get_running_loop()
        if session_manager is None:
            yield
            return
        async with session_manager.run():
            await manager.start(wait_seconds=upstream_wait_seconds)
            try:
                yield
            finally:
                await manager.stop()

    app = Starlette(routes=routes, lifespan=lifespan)
    # Starlette wraps in reverse order of addition, so the request-id middleware added last is
    # the outermost: a 401 from the auth middleware still carries a request id.
    app.add_middleware(
        AuthMiddleware,
        authenticator=authenticator,
        protected_prefixes=PROTECTED_PREFIXES,
        resource_metadata_url=(
            f"{settings.warden_resource_url.rsplit('/mcp', 1)[0]}{PROTECTED_RESOURCE_PATH}"
        ),
    )
    app.add_middleware(RequestIdMiddleware)
    app.state.settings = settings
    app.state.database = db
    app.state.jwt_keys = jwt_keys
    app.state.tokens = token_service
    app.state.authenticator = authenticator
    app.state.readiness = checks
    app.state.gateway_config = gateway
    app.state.servers_config = servers
    app.state.registry = registry
    app.state.upstreams = manager
    app.state.mcp_server = mcp_server
    return app


__all__ = [
    "JWKS_PATH",
    "MCP_PATH",
    "PROTECTED_PREFIXES",
    "PROTECTED_RESOURCE_PATH",
    "RequestIdMiddleware",
    "build_pipeline_factory",
    "build_upstream_manager",
    "create_app",
    "default_readiness",
]
