"""The admin API.

Everything here sits behind `/admin`, which the auth middleware protects, and behind an
explicit `admin` role check. Authentication alone is not authorisation: a valid `reader`
credential must not reach an admin endpoint.
"""

from __future__ import annotations

import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from warden.auth.middleware import principal_from_request
from warden.logging import get_logger
from warden.pipeline import Principal
from warden.policy.store import PolicyStore
from warden.upstream.manager import UpstreamManager

logger = get_logger(__name__)

ADMIN_ROLE = "admin"

Handler = Callable[[Request], Awaitable[Response]]


def forbidden(reason: str) -> Response:
    return JSONResponse({"error": "forbidden", "error_description": reason}, status_code=403)


def admin_principal(request: Request) -> Principal | None:
    """The caller, if they hold the admin role."""
    principal = principal_from_request(request)
    if principal is None or not principal.has_role(ADMIN_ROLE):
        return None
    return principal


def require_admin(handler: Handler) -> Handler:
    """Refuse anyone without the admin role with a 403, and log the attempt."""

    async def wrapped(request: Request) -> Response:
        principal = admin_principal(request)
        if principal is None:
            caller = principal_from_request(request)
            logger.warning(
                "admin endpoint refused",
                extra={
                    "warden": {
                        "path": request.url.path,
                        "principal": caller.user_id if caller else None,
                        "roles": list(caller.roles) if caller else [],
                    }
                },
            )
            return forbidden(f"the '{ADMIN_ROLE}' role is required")
        return await handler(request)

    wrapped.__name__ = getattr(handler, "__name__", "admin_handler")
    return wrapped


@dataclass(slots=True)
class AdminDeps:
    """What the admin endpoints need. Extended as later phases add surfaces."""

    policies: PolicyStore
    upstreams: UpstreamManager


def build_admin_routes(deps: AdminDeps) -> list[Route]:
    """The admin routes, each already wrapped in the role check."""

    @require_admin
    async def reload_policies(_: Request) -> Response:
        changed, message = deps.policies.reload()
        status = 200 if not message.startswith("rejected") else 409
        return JSONResponse(
            {"changed": changed, "message": message, "policy": deps.policies.status()},
            status_code=status,
        )

    @require_admin
    async def policy_status(_: Request) -> Response:
        return JSONResponse(
            {"policy": deps.policies.status(), "rules": deps.policies.engine.describe()}
        )

    @require_admin
    async def upstream_status(_: Request) -> Response:
        return JSONResponse(
            {
                "upstreams": [health.as_dict() for health in deps.upstreams.health().values()],
            }
        )

    @require_admin
    async def refresh_tools(_: Request) -> Response:
        await deps.upstreams.refresh_all()
        return JSONResponse(
            {"upstreams": [health.as_dict() for health in deps.upstreams.health().values()]}
        )

    return [
        Route("/admin/reload", reload_policies, methods=["POST"]),
        Route("/admin/policy", policy_status, methods=["GET"]),
        Route("/admin/upstreams", upstream_status, methods=["GET"]),
        Route("/admin/upstreams/refresh", refresh_tools, methods=["POST"]),
    ]


def install_sighup_reload(policies: PolicyStore) -> Callable[[], None]:
    """Reload the policy on SIGHUP. Returns a function that removes the handler again.

    SIGHUP is the convention for "re-read your configuration", and it works where an HTTP call
    does not: a local operator with a shell but no admin credential.
    """
    import asyncio
    import signal

    def handler() -> None:
        changed, message = policies.reload()
        logger.warning(
            "SIGHUP policy reload", extra={"warden": {"changed": changed, "message": message}}
        )

    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGHUP, handler)
    except (NotImplementedError, RuntimeError, AttributeError, ValueError) as exc:
        # Windows has no SIGHUP, and a non-main thread cannot install one. Not fatal: the
        # admin endpoint still works.
        logger.info("SIGHUP reload not available", extra={"warden": {"reason": str(exc)}})
        return lambda: None

    def remove() -> None:
        with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
            loop.remove_signal_handler(signal.SIGHUP)

    return remove


__all__ = [
    "ADMIN_ROLE",
    "AdminDeps",
    "admin_principal",
    "build_admin_routes",
    "install_sighup_reload",
    "require_admin",
]
