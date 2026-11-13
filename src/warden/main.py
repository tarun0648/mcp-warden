"""The gateway's HTTP application factory.

Phase 0 serves only /healthz and /readyz. Later phases mount the MCP endpoint at /mcp, the
admin API under /admin and the approval UI at /approvals onto the same app.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from warden.config import Settings
from warden.health import Readiness, postgres_check, redis_check
from warden.logging import configure_logging, get_logger, request_id_var

logger = get_logger(__name__)

REQUEST_ID_HEADER = "x-request-id"


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


def create_app(settings: Settings, *, readiness: Readiness | None = None) -> Starlette:
    """Build the Starlette application for the given settings."""
    configure_logging(settings.log_level)
    checks = readiness if readiness is not None else default_readiness(settings)
    routes = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", make_readyz(checks), methods=["GET"]),
    ]
    app = Starlette(routes=routes)
    app.add_middleware(RequestIdMiddleware)
    app.state.settings = settings
    app.state.readiness = checks
    return app
