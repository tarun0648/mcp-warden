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
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from ipaddress import IPv4Network, IPv6Network, ip_address
from typing import Any

from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from warden.admin import AdminDeps, admin_principal, build_admin_routes, install_sighup_reload
from warden.approval.stage import Approval
from warden.approval.store import ApprovalStore
from warden.approval.web import ApprovalSecurityHeaders, build_approval_routes
from warden.audit.log import AuditLog
from warden.audit.stage import AuditWriteAhead, audit_finish_hook
from warden.auth.api_keys import ApiKeyStore
from warden.auth.jwt_keys import JwtKeyStore, KeyStoreError
from warden.auth.middleware import Authenticator, AuthMiddleware, principal_from_request
from warden.auth.stage import Authenticate
from warden.auth.tokens import (
    RedisRevocationStore,
    RevocationStore,
    TokenConfig,
    TokenService,
)
from warden.config import (
    GatewayConfig,
    LimitsConfig,
    ScanConfig,
    ServersConfig,
    Settings,
    load_gateway_config,
    load_servers_config,
)
from warden.db.engine import Database
from warden.health import Readiness, postgres_check, redis_check
from warden.http_limits import RequestLimitsMiddleware
from warden.logging import configure_logging, get_logger, request_id_var
from warden.pipeline import Pipeline, Principal
from warden.policy.defaults import ApplySchemaDefaults
from warden.policy.stage import Policy
from warden.policy.store import PolicyStore
from warden.proxy.registry import ToolRegistry
from warden.proxy.server import GatewayDeps, build_mcp_server
from warden.proxy.stages import ForwardToUpstream, ResolveTool
from warden.ratelimit.limiter import RateLimiter
from warden.ratelimit.stage import OutputLimit, RateLimit
from warden.scan.classifier import InjectionClassifier
from warden.scan.definitions import DefinitionScanner
from warden.scan.output import OutputScanner
from warden.scan.pinning import PinStore
from warden.scan.stages import ArgumentDLP, DefinitionIntegrity, OutputScan
from warden.telemetry.metrics import Metrics
from warden.telemetry.tracing import configure_tracing
from warden.upstream.manager import UpstreamManager

logger = get_logger(__name__)

REQUEST_ID_HEADER = "x-request-id"
MCP_PATH = "/mcp"
JWKS_PATH = "/.well-known/jwks.json"
METRICS_PATH = "/metrics"
PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource"


def protected_resource_paths(resource_url: str) -> tuple[str, ...]:
    """Where RFC 9728 metadata for `resource_url` must be served.

    RFC 9728 section 3.1 inserts `/.well-known/oauth-protected-resource` *between the host and
    the path* of the resource identifier, so a resource of `http://host:8080/mcp` publishes its
    metadata at `/.well-known/oauth-protected-resource/mcp`, not at the bare well-known path.
    Serving only the bare path is what the MCP Inspector trips over, and it is the first thing
    any OAuth-capable client does.

    Both are returned, most specific first. The bare path is kept because a client that was
    given the origin rather than the full endpoint asks for it, and because that is the correct
    location for a deployment whose resource URL has no path at all; in that case the two
    collapse to one entry.
    """
    from urllib.parse import urlsplit

    path = urlsplit(resource_url).path.rstrip("/")
    if not path:
        return (PROTECTED_RESOURCE_PATH,)
    return (f"{PROTECTED_RESOURCE_PATH}{path}", PROTECTED_RESOURCE_PATH)


def protected_resource_metadata_url(resource_url: str) -> str:
    """The absolute URL to advertise in `WWW-Authenticate: ... resource_metadata=`."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(resource_url)
    origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    return f"{origin}{protected_resource_paths(resource_url)[0]}"


#: Paths that require a credential. Public by design: the health checks (a load balancer has no
#: credential) and the two well-known documents (a client must read them to get one).
PROTECTED_PREFIXES = (MCP_PATH, "/admin")
#: A credential here is verified if present and not required. See `AuthMiddleware`.
OPTIONAL_AUTH_PREFIXES = (METRICS_PATH,)
#: Every Redis operation is bounded, explicitly. The locked redis-py (8.1.0) already defaults
#: both timeouts to 5 s - measured: a client with no settings gave up on a silent server after
#: 5.0 s - but the declared range `redis>=5.2` admits older releases whose defaults differ, and
#: a security property should not ride on a dependency's default. Set here, a Redis that accepts
#: the connection and then stops answering raises within 2 s, and the limiter denies exactly as
#: it does when Redis is down.
REDIS_CONNECT_TIMEOUT_SECONDS = 2.0
REDIS_SOCKET_TIMEOUT_SECONDS = 2.0


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
                "resource_documentation": "https://github.com/tarun0648/mcp-warden",
            },
            headers={"Cache-Control": "public, max-age=300"},
        )

    return metadata


def _in_networks(host: str, networks: Sequence[IPv4Network | IPv6Network]) -> bool:
    """True when `host` is an IP address inside one of `networks`. Hostnames never match."""
    if not networks:
        return False
    try:
        address = ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in networks)


def make_metrics(
    metrics: Metrics,
    *,
    upstreams: UpstreamManager,
    pins: PinStore,
    approvals: ApprovalStore,
    allow_localhost: bool,
    allow_networks: Sequence[IPv4Network | IPv6Network] = (),
) -> Callable[[Request], Awaitable[Response]]:
    """Serve Prometheus metrics, to localhost, an allowed scraper network, or an admin.

    Not public: the series names and label values describe which tools exist, which are
    quarantined and what is being refused - useful to an operator and equally useful to someone
    deciding what to attack. A scrape from loopback is allowed without a credential because
    that is how a sidecar Prometheus reaches it; anything else needs the admin role.
    """

    async def endpoint(request: Request) -> Response:
        client_host = request.client.host if request.client else ""
        local = client_host in ("127.0.0.1", "::1", "localhost", "testclient")
        if not ((allow_localhost and local) or _in_networks(client_host, allow_networks)):
            principal = admin_principal(request)
            if principal is None:
                return JSONResponse(
                    {
                        "error": "forbidden",
                        "error_description": "metrics are available to localhost or the admin role",
                    },
                    status_code=403,
                )

        # Gauges describe "right now", so they are sampled at scrape time rather than kept in
        # step by every code path that might change them.
        metrics.set_upstream_health(upstreams.health())
        metrics.set_quarantined(len(pins.quarantined_names))
        try:
            metrics.set_pending_approvals(len(await approvals.pending()))
        except Exception:
            logger.warning("could not count pending approvals for /metrics")
        body, content_type = metrics.render()
        return Response(body, media_type=content_type)

    return endpoint


def build_redis(settings: Settings) -> Any:
    """One Redis client for the whole process: the limiter and the revocation list share it."""
    import redis.asyncio as aioredis

    return aioredis.from_url(
        settings.redis_url,
        socket_connect_timeout=REDIS_CONNECT_TIMEOUT_SECONDS,
        socket_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
    )


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
    registry: ToolRegistry,
    servers_config: ServersConfig,
    upstreams: UpstreamManager,
    policies: PolicyStore,
    limiter: RateLimiter,
    limits: LimitsConfig,
    audit: AuditLog,
    pins: PinStore,
    scan_config: ScanConfig,
    output_scanner: OutputScanner,
    approvals: ApprovalStore,
    approval_wait_seconds: float,
    metrics: Metrics,
) -> Callable[[], Pipeline]:
    """The pipeline, in the one order that is the security contract.

    The full order CLAUDE.md specifies: authenticate, resolve, definitions, policy, ratelimit,
    dlp, approval, audit (write-ahead), forward, output_limit, output_scan - with the audit
    writer as a finish hook so every request leaves a record whatever happens.

    Three placements are deliberate:

    * `definitions` runs before `policy`, so a quarantined tool is refused for the same reason
      whoever asks, rather than reporting "no permission" to one caller and "quarantined" to
      another.
    * `defaults` sits between them: after `definitions`, so it only ever reads a pinned
      definition; before `policy`, so the constraints check the arguments that will actually
      be forwarded, including any the caller left to the schema's default.
    * `approval` runs after `dlp`, so a call that carries a secret is refused outright rather
      than put in front of a human to rubber-stamp; and before the write-ahead row, because a
      call waiting for a human has not started.
    * the write-ahead row is the last thing before `forward`: everything that can refuse the
      call cheaply has already run, so the log is not filled with rows for calls that were
      never going to happen, and nothing that *can* reach an upstream runs before it.
    """
    authenticate = Authenticate()
    resolve = ResolveTool(registry, servers_config)
    definitions = DefinitionIntegrity(pins)
    defaults = ApplySchemaDefaults(registry)
    policy = Policy(policies)
    ratelimit = RateLimit(limiter, limits)
    dlp = ArgumentDLP(scan_config)
    approval = Approval(approvals, wait_seconds=approval_wait_seconds)
    write_ahead = AuditWriteAhead(audit)
    forward = ForwardToUpstream(upstreams)
    output_limit = OutputLimit(limits)
    output_scan = OutputScan(output_scanner, servers_config)
    finish = audit_finish_hook(audit)

    async def record_metrics(ctx: Any) -> None:
        metrics.record_request(ctx, known_tools=registry)

    def factory() -> Pipeline:
        return Pipeline(
            [
                authenticate,
                resolve,
                definitions,
                defaults,
                policy,
                ratelimit,
                dlp,
                approval,
                write_ahead,
                forward,
                output_limit,
                output_scan,
            ],
            [finish, record_metrics],
        )

    return factory


def build_tool_filter(policies: PolicyStore, pins: PinStore) -> Callable[..., list[Any]]:
    """Filter `tools/list` down to what the caller could call, and what we trust.

    Two filters, in this order:

    * quarantined tools are removed for everyone - a model that can see a tool keeps trying it,
      and for a poisoned tool the description *is* the attack, so hiding it matters as much as
      refusing the call;
    * then the policy, where argument constraints are ignored but a tool whose only matching
      rule is a deny is hidden entirely: a reader should not learn that `files__delete_file`
      exists.
    """

    def filter_tools(principal: Principal | None, tools: list[Any]) -> list[Any]:
        usable = [tool for tool in tools if not pins.is_quarantined(tool.name)]
        allowed = set(policies.engine.visible_tools(principal, [tool.name for tool in usable]))
        return [tool for tool in usable if tool.name in allowed]

    return filter_tools


async def _close_owned(db: Database | None, redis_client: Any | None) -> None:
    """Release the connections this app opened.

    Without this, the engine's pool is collected after the loop has gone, which surfaces as
    "Event loop is closed" during shutdown - noise in tests, and a leaked connection in a
    process that creates more than one app.
    """
    if db is not None:
        with contextlib.suppress(Exception):
            await db.dispose()
    if redis_client is not None:
        closer = getattr(redis_client, "aclose", None) or getattr(redis_client, "close", None)
        if closer is not None:
            with contextlib.suppress(Exception):
                await closer()


def _select_pipeline(
    wanted: Sequence[str] | None, factory: Callable[[], Pipeline]
) -> Callable[[], Pipeline]:
    """Keep only the named stages, in the pipeline's own order.

    Used by the latency benchmark to measure a cut-down gateway. The order is never taken from
    the caller - it is always the pipeline's - so a benchmark cannot accidentally measure a
    configuration that could not exist. The finish hooks are kept either way, because a
    gateway that does not write its audit log is not a configuration anyone would deploy.
    """
    if wanted is None:
        return factory
    allowed = set(wanted)

    def reduced() -> Pipeline:
        full = factory()
        return Pipeline(
            [stage for stage in full.stages if stage.name in allowed], full.finish_hooks
        )

    return reduced


def create_app(
    settings: Settings,
    *,
    readiness: Readiness | None = None,
    gateway_config: GatewayConfig | None = None,
    servers_config: ServersConfig | None = None,
    upstreams: UpstreamManager | None = None,
    policy_store: PolicyStore | None = None,
    database: Database | None = None,
    redis: Any | None = None,
    injection_classifier: InjectionClassifier | None = None,
    metrics: Metrics | None = None,
    #: Replace the pipeline entirely. The latency benchmark uses this to measure a
    #: cut-down gateway (auth and policy only) against the full one, which is the only way to
    #: say what each stage costs rather than what the whole thing costs.
    pipeline_stages: Sequence[str] | None = None,
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

    policies = (
        policy_store if policy_store is not None else PolicyStore(settings.policies_yaml, servers)
    )

    # Anything the caller passed in belongs to the caller; only what we build here is ours to
    # close on shutdown.
    owned_redis = redis is None
    owned_database = database is None
    # Built before the classifier, which reports its timings into it.
    _shared_metrics = metrics if metrics is not None else Metrics()
    redis_client = redis if redis is not None else build_redis(settings)
    limiter = RateLimiter(redis_client, gateway.limits)

    db = database if database is not None else Database(settings.database_url)
    audit = AuditLog(db)

    classifier = (
        injection_classifier
        if injection_classifier is not None
        else InjectionClassifier(
            enabled=gateway.scan.classifier_enabled or settings.classifier_enabled,
            model_id=gateway.scan.classifier_model,
            revision=gateway.scan.classifier_revision,
            device=gateway.scan.classifier_device,
            timeout_seconds=gateway.scan.classifier_timeout_seconds,
            on_timing=(metrics or _shared_metrics).observe_classifier,
        )
    )
    approvals = ApprovalStore(
        db,
        notifier=redis_client,
        expiry_seconds=gateway.approval.expiry_seconds,
        allow_self_approval=gateway.approval.allow_self_approval,
        on_event=audit.record_approval_event,
    )
    pins = PinStore(db, DefinitionScanner(gateway.scan, classifier))
    output_scanner = OutputScanner(gateway.scan, classifier)
    telemetry = metrics if metrics is not None else _shared_metrics
    trusted = [upstream.name for upstream in servers.upstreams if upstream.trusted]

    async def on_tools_changed(tools_by_upstream: Any) -> None:
        """Re-pin and re-register whenever an upstream's listing changes.

        Pins are reconciled *before* the registry is rebuilt. During the gap the registry still
        holds the previously approved definitions, which is the safe direction: the alternative
        would briefly advertise a definition that has just changed under us.
        """
        await pins.reconcile(tools_by_upstream, trusted_servers=trusted)
        registry.replace(tools_by_upstream)

    manager.on_tools_changed = on_tools_changed
    jwt_keys = JwtKeyStore(settings.jwt_key_dir)
    token_service = TokenService(
        jwt_keys,
        TokenConfig(
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            default_ttl_seconds=settings.jwt_default_ttl_seconds,
            clock_skew_seconds=settings.jwt_clock_skew_seconds,
        ),
        revocations if revocations is not None else RedisRevocationStore(redis_client),
    )
    authenticator = Authenticator(api_keys=ApiKeyStore(db), tokens=token_service)

    routes.extend(
        build_admin_routes(
            AdminDeps(
                policies=policies,
                upstreams=manager,
                audit=audit,
                limiter=limiter,
                pins=pins,
                approvals=approvals,
            )
        )
    )
    routes.extend(build_approval_routes(approvals=approvals, api_keys=ApiKeyStore(db)))
    routes.append(Route(JWKS_PATH, make_jwks(jwt_keys), methods=["GET"]))
    if settings.metrics_enabled:
        routes.append(
            Route(
                METRICS_PATH,
                make_metrics(
                    telemetry,
                    upstreams=manager,
                    pins=pins,
                    approvals=approvals,
                    allow_localhost=settings.metrics_allow_localhost,
                    allow_networks=settings.metrics_networks(),
                ),
                methods=["GET"],
            )
        )
    metadata_handler = make_protected_resource_metadata(settings)
    for well_known in protected_resource_paths(settings.warden_resource_url):
        routes.append(Route(well_known, metadata_handler, methods=["GET"]))

    mcp_server: Server[object] | None = None
    session_manager: StreamableHTTPSessionManager | None = None

    if mount_mcp:
        deps = GatewayDeps(
            settings_name="mcp-warden",
            gateway_config=gateway,
            servers_config=servers,
            registry=registry,
            upstreams=manager,
            pipeline_factory=_select_pipeline(
                pipeline_stages,
                build_pipeline_factory(
                    registry,
                    servers,
                    manager,
                    policies,
                    limiter,
                    gateway.limits,
                    audit,
                    pins,
                    gateway.scan,
                    output_scanner,
                    approvals,
                    gateway.approval.wait_seconds,
                    telemetry,
                ),
            ),
            principal_resolver=lambda ctx: principal_from_request(ctx.request),
            tool_filter=build_tool_filter(policies, pins),
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
        remove_sighup = install_sighup_reload(policies)
        try:
            await db.prepare()
            if session_manager is None:
                # Health-only app: there are no tools to protect and no MCP endpoint, so the
                # pin store and the classifier are not consulted.
                yield
            else:
                # Deliberately not guarded: a gateway that cannot read which tools are
                # quarantined must refuse to start rather than start without knowing.
                configure_tracing(settings)
                await pins.load_quarantine_view()
                if classifier.enabled:
                    await classifier.warm_up()
                async with session_manager.run():
                    await manager.start(wait_seconds=upstream_wait_seconds)
                    try:
                        yield
                    finally:
                        await manager.stop()
        finally:
            remove_sighup()
            await _close_owned(
                db if owned_database else None, redis_client if owned_redis else None
            )

    app = Starlette(routes=routes, lifespan=lifespan)
    # Starlette wraps in reverse order of addition, so the request-id middleware added last is
    # the outermost: a 401 from the auth middleware still carries a request id.
    app.add_middleware(
        AuthMiddleware,
        authenticator=authenticator,
        protected_prefixes=PROTECTED_PREFIXES,
        optional_prefixes=OPTIONAL_AUTH_PREFIXES,
        resource_metadata_url=protected_resource_metadata_url(settings.warden_resource_url),
    )
    app.add_middleware(ApprovalSecurityHeaders, prefix="/approvals")
    # Inside the request-id middleware so a 413 still carries an id, outside auth so an
    # oversized body is refused before anything parses it.
    app.add_middleware(
        RequestLimitsMiddleware,
        max_body_bytes=gateway.limits.max_request_body_bytes,
        mcp_path=MCP_PATH,
    )
    app.add_middleware(RequestIdMiddleware)
    app.state.settings = settings
    app.state.database = db
    app.state.jwt_keys = jwt_keys
    app.state.tokens = token_service
    app.state.authenticator = authenticator
    app.state.policies = policies
    app.state.limiter = limiter
    app.state.audit = audit
    app.state.pins = pins
    app.state.metrics = telemetry
    app.state.approvals = approvals
    app.state.classifier = classifier
    app.state.redis = redis_client
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
    "OPTIONAL_AUTH_PREFIXES",
    "PROTECTED_PREFIXES",
    "PROTECTED_RESOURCE_PATH",
    "RequestIdMiddleware",
    "build_pipeline_factory",
    "build_tool_filter",
    "build_upstream_manager",
    "create_app",
    "default_readiness",
    "protected_resource_metadata_url",
    "protected_resource_paths",
]
