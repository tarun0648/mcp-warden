"""The admin API.

Everything here sits behind `/admin`, which the auth middleware protects, and behind an
explicit `admin` role check. Authentication alone is not authorisation: a valid `reader`
credential must not reach an admin endpoint.
"""

from __future__ import annotations

import contextlib
import csv
import io
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from warden.audit.log import DEFAULT_PAGE_SIZE, AuditFilters, AuditLog
from warden.auth.middleware import principal_from_request
from warden.config import split_namespaced
from warden.logging import get_logger
from warden.pipeline import Principal
from warden.policy.store import PolicyStore
from warden.ratelimit.limiter import RateLimiter
from warden.scan.definitions import diff_definitions
from warden.scan.pinning import PinStore
from warden.upstream.manager import UpstreamManager

logger = get_logger(__name__)

ADMIN_ROLE = "admin"

Handler = Callable[[Request], Awaitable[Response]]


def _bad_request(reason: str) -> Response:
    return JSONResponse({"error": "bad_request", "error_description": reason}, status_code=400)


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
    audit: AuditLog
    limiter: RateLimiter
    pins: PinStore


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

    @require_admin
    async def audit_query(request: Request) -> Response:
        filters, problem = _audit_filters(request)
        if problem is not None:
            return JSONResponse(
                {"error": "bad_request", "error_description": problem}, status_code=400
            )
        cursor, cursor_problem = _int_param(request, "cursor")
        if cursor_problem is not None:
            return JSONResponse(
                {"error": "bad_request", "error_description": cursor_problem}, status_code=400
            )
        limit, limit_problem = _int_param(request, "limit")
        if limit_problem is not None:
            return JSONResponse(
                {"error": "bad_request", "error_description": limit_problem}, status_code=400
            )
        page = await deps.audit.query(filters, cursor=cursor, limit=limit or DEFAULT_PAGE_SIZE)
        if request.query_params.get("format") == "csv":
            return _csv_response(page.rows)
        return JSONResponse({"rows": page.rows, "next_cursor": page.next_cursor})

    @require_admin
    async def audit_verify(_: Request) -> Response:
        result = await deps.audit.verify()
        body: dict[str, Any] = {
            "ok": result.ok,
            "rows_checked": result.rows_checked,
            "head_hash": result.head_hash,
        }
        if result.first_break is not None:
            body["first_break"] = {
                "row_id": result.first_break.row_id,
                "kind": result.first_break.kind,
                "detail": result.first_break.detail,
            }
        return JSONResponse(body, status_code=200 if result.ok else 409)

    @require_admin
    async def usage(request: Request) -> Response:
        principal = request.query_params.get("user")
        if not principal:
            return JSONResponse(
                {"error": "bad_request", "error_description": "a 'user' parameter is required"},
                status_code=400,
            )
        return JSONResponse({"user": principal, "usage": await deps.limiter.usage(principal)})

    @require_admin
    async def list_pins(request: Request) -> Response:
        status = request.query_params.get("status")
        rows = await deps.pins.list_pins(status=status)
        return JSONResponse({"pins": rows, "quarantined": list(deps.pins.quarantined_names)})

    @require_admin
    async def pin_diff(request: Request) -> Response:
        parts = split_namespaced(request.path_params["tool"])
        if parts is None:
            return _bad_request("the tool must be named <server>__<tool>")
        pin = await deps.pins.get_pin(*parts)
        pair = await deps.pins.definitions_for_diff(*parts)
        if pin is None or pair is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        previous, current = pair
        scan = pin.get("scan") or {}
        return JSONResponse(
            {
                "tool": pin["name"],
                "status": pin["status"],
                "sha256": pin["sha256"],
                "previous_sha256": scan.get("previous_sha256"),
                "diff": diff_definitions(previous, current),
                "scan": {key: value for key, value in scan.items() if key != "previous_definition"},
            }
        )

    @require_admin
    async def approve_pin(request: Request) -> Response:
        principal = admin_principal(request)
        assert principal is not None  # require_admin guarantees it
        parts = split_namespaced(request.path_params["tool"])
        if parts is None:
            return _bad_request("the tool must be named <server>__<tool>")
        if not await deps.pins.approve(*parts, approved_by=principal.user_id):
            return JSONResponse({"error": "not_found"}, status_code=404)
        return JSONResponse({"approved": request.path_params["tool"]})

    @require_admin
    async def quarantine_pin(request: Request) -> Response:
        principal = admin_principal(request)
        assert principal is not None
        parts = split_namespaced(request.path_params["tool"])
        if parts is None:
            return _bad_request("the tool must be named <server>__<tool>")
        reason = request.query_params.get("reason", "quarantined by an operator")
        if not await deps.pins.quarantine(*parts, by=principal.user_id, reason=reason):
            return JSONResponse({"error": "not_found"}, status_code=404)
        return JSONResponse({"quarantined": request.path_params["tool"]})

    return [
        Route("/admin/reload", reload_policies, methods=["POST"]),
        Route("/admin/pins", list_pins, methods=["GET"]),
        Route("/admin/pins/{tool}", pin_diff, methods=["GET"]),
        Route("/admin/pins/{tool}/approve", approve_pin, methods=["POST"]),
        Route("/admin/pins/{tool}/quarantine", quarantine_pin, methods=["POST"]),
        Route("/admin/audit", audit_query, methods=["GET"]),
        Route("/admin/audit/verify", audit_verify, methods=["GET"]),
        Route("/admin/usage", usage, methods=["GET"]),
        Route("/admin/policy", policy_status, methods=["GET"]),
        Route("/admin/upstreams", upstream_status, methods=["GET"]),
        Route("/admin/upstreams/refresh", refresh_tools, methods=["POST"]),
    ]


#: Columns of the CSV export, in a fixed order so a saved spreadsheet keeps working.
CSV_COLUMNS: Final = (
    "id",
    "ts",
    "request_id",
    "event",
    "principal_id",
    "auth_method",
    "method",
    "tool",
    "upstream",
    "risk",
    "decision",
    "reason_code",
    "matched_rule",
    "result_bytes",
    "args_sha256",
    "result_sha256",
    "prev_hash",
    "row_hash",
)


def _csv_response(rows: list[dict[str, Any]]) -> Response:
    """Export rows as CSV.

    `args_redacted`, `stage_timings_ms` and `scan_flags` are left out: they are nested JSON and
    would need quoting rules that differ per spreadsheet. The JSON endpoint carries them.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: row.get(column) for column in CSV_COLUMNS})
    return Response(
        buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="warden-audit.csv"'},
    )


def _audit_filters(request: Request) -> tuple[AuditFilters, str | None]:
    """Build filters from the query string, rejecting an unparseable timestamp."""
    params = request.query_params
    since, since_problem = _timestamp_param(params.get("since"), "since")
    if since_problem is not None:
        return AuditFilters(), since_problem
    until, until_problem = _timestamp_param(params.get("until"), "until")
    if until_problem is not None:
        return AuditFilters(), until_problem
    return (
        AuditFilters(
            principal_id=params.get("user"),
            tool=params.get("tool"),
            decision=params.get("decision"),
            event=params.get("event"),
            reason_code=params.get("reason_code"),
            request_id=params.get("request_id"),
            since=since,
            until=until,
        ),
        None,
    )


def _timestamp_param(raw: str | None, name: str) -> tuple[datetime | None, str | None]:
    if not raw:
        return None, None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None, f"'{name}' must be an ISO-8601 timestamp, for example 2026-11-13T00:00:00Z"
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)), None


def _int_param(request: Request, name: str) -> tuple[int | None, str | None]:
    raw = request.query_params.get(name)
    if not raw:
        return None, None
    try:
        return int(raw), None
    except ValueError:
        return None, f"'{name}' must be an integer"


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
    "CSV_COLUMNS",
    "AdminDeps",
    "admin_principal",
    "build_admin_routes",
    "install_sighup_reload",
    "require_admin",
]
