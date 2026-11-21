"""The console, served by the gateway at /console - for every role.

Anyone with an API key can sign in, and sees what that key's roles allow:

| Page | admin | any other role |
| --- | --- | --- |
| Overview | the whole gateway | their own tools, decisions and requests |
| Playground | call any tool as any role | call tools as one of their own roles |
| Activity | the full audit log, verify, CSV | their own audit rows only |
| Approvals | the queue, approve / deny | their own requests, read-only |
| Tools, API keys, Policy | full management | 403 |

**Authorization is enforced per route, on the server.** The navigation hides what a role cannot
use, but every handler is wrapped in a guard that checks the session's roles again; a reader
who types `/console/keys` gets 403, not a page with the links removed. Where a non-admin may
see a page, the data is narrowed on the server too - their audit query is forced to their own
principal id, whatever the URL says.

Built the way the approval page is, for the same reasons:

* **Server-rendered Jinja + HTMX, no JavaScript of our own.** The CSP allows one script - the
  pinned, integrity-checked htmx file - and no inline script or style.
* **Session cookie, not a credential in the page.** The API key is exchanged once for an opaque
  `HttpOnly`, `SameSite=Strict` cookie scoped to /console. The key never reaches a form value,
  URL or the DOM afterwards.
* **CSRF token on every POST**, checked in the one wrapper every action goes through.
* **Every value is attacker-controlled** - tool names, descriptions, arguments, audit fields -
  so autoescape is on, `StrictUndefined` catches a misspelt variable, no template uses
  `|safe`, and upstream text goes through `excerpt`, which makes invisible and
  direction-changing characters visible instead of rendering them.

Sessions live in memory: a restart signs everyone out, which is the safe direction.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlencode

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from warden.approval.store import ApprovalStore
from warden.approval.web import HTMX_URL, _is_secure_origin
from warden.audit.log import AuditFilters, AuditLog
from warden.auth.api_keys import ApiKeyStore, InvalidApiKey
from warden.config import ServersConfig, split_namespaced
from warden.console.playground import JobStore, console_principal, start_job, suggested_arguments
from warden.errors import ReasonCode
from warden.logging import get_logger
from warden.pipeline import Decision, Pipeline
from warden.policy.store import PolicyStore
from warden.proxy.registry import ToolRegistry
from warden.scan.definitions import diff_definitions
from warden.scan.pinning import PinStore
from warden.upstream.manager import UpstreamManager

logger = get_logger(__name__)

CONSOLE_PREFIX: Final = "/console"
SESSION_COOKIE: Final = "warden_console_session"
CSRF_FIELD: Final = "csrf_token"
ADMIN_ROLE: Final = "admin"
SESSION_TTL_SECONDS: Final = 8 * 60 * 60
TEMPLATE_DIR: Final = Path(__file__).parent / "templates"
STATIC_DIR: Final = Path(__file__).parent / "static"
STYLESHEET_PATH: Final = f"{CONSOLE_PREFIX}/static/console.css"

AUDIT_PAGE_SIZE: Final = 50
#: How many recent audit rows the overview summarises.
OVERVIEW_WINDOW: Final = 200
MAX_PLAYGROUND_ARGUMENT_BYTES: Final = 64 * 1024
#: A user id for a new key: nothing that needs escaping anywhere it ends up.
USER_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")

#: (key, label, path, admin only)
NAV: Final[tuple[tuple[str, str, str, bool], ...]] = (
    ("overview", "Overview", CONSOLE_PREFIX, False),
    ("playground", "Playground", f"{CONSOLE_PREFIX}/playground", False),
    ("audit", "Activity", f"{CONSOLE_PREFIX}/audit", False),
    ("approvals", "Approvals", f"{CONSOLE_PREFIX}/approvals", False),
    ("tools", "Tools", f"{CONSOLE_PREFIX}/tools", True),
    ("keys", "API keys", f"{CONSOLE_PREFIX}/keys", True),
    ("policy", "Policy", f"{CONSOLE_PREFIX}/policy", True),
)


# ----------------------------------------------------------------------------------------------
# Sessions
# ----------------------------------------------------------------------------------------------


@dataclass(slots=True)
class ConsoleSession:
    """One signed-in user. Holds identifiers only - never the key they signed in with."""

    user_id: str
    roles: tuple[str, ...]
    csrf_token: str
    created_at: float = field(default_factory=time.time)

    @property
    def expired(self) -> bool:
        return time.time() - self.created_at > SESSION_TTL_SECONDS

    @property
    def is_admin(self) -> bool:
        return ADMIN_ROLE in self.roles


class ConsoleSessions:
    """In-memory sessions keyed by an opaque token."""

    def __init__(self) -> None:
        self._sessions: dict[str, ConsoleSession] = {}

    def create(self, user_id: str, roles: tuple[str, ...]) -> tuple[str, ConsoleSession]:
        token = secrets.token_urlsafe(32)
        session = ConsoleSession(
            user_id=user_id, roles=tuple(roles), csrf_token=secrets.token_urlsafe(32)
        )
        self._sessions[token] = session
        return token, session

    def get(self, token: str | None) -> ConsoleSession | None:
        if not token:
            return None
        session = self._sessions.get(token)
        if session is None:
            return None
        if session.expired:
            del self._sessions[token]
            return None
        return session

    def destroy(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)

    def __len__(self) -> int:
        return len(self._sessions)


@dataclass(slots=True)
class ConsoleDeps:
    """What the console reads and changes - the same objects the gateway itself uses."""

    api_keys: ApiKeyStore
    approvals: ApprovalStore
    audit: AuditLog
    pins: PinStore
    policies: PolicyStore
    registry: ToolRegistry
    upstreams: UpstreamManager
    servers: ServersConfig
    #: None when the MCP endpoint is not mounted; the playground then says it is unavailable.
    pipeline_factory: Callable[[], Pipeline] | None
    tool_filter: Callable[..., list[Any]]
    sessions: ConsoleSessions = field(default_factory=ConsoleSessions)
    jobs: JobStore = field(default_factory=JobStore)


# ----------------------------------------------------------------------------------------------
# Template helpers
# ----------------------------------------------------------------------------------------------


def _pretty(value: Any) -> str:
    """JSON for a <pre> block, as a plain string so autoescape still applies."""
    try:
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _ago(value: Any) -> str:
    """'3 min ago' from an ISO timestamp or epoch seconds; '' when unparseable."""
    try:
        if isinstance(value, int | float):
            moment = datetime.fromtimestamp(float(value), tz=UTC)
        else:
            moment = datetime.fromisoformat(str(value))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=UTC)
    except (TypeError, ValueError, OSError):
        return ""
    seconds = int((datetime.now(UTC) - moment).total_seconds())
    if seconds < 0:
        ahead = -seconds
        if ahead < 60:
            return f"in {ahead}s"
        if ahead < 3600:
            return f"in {ahead // 60} min"
        return f"in {ahead // 3600} h"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


def _clock(value: Any) -> str:
    """'2026-11-21 14:03:07 UTC' from an ISO timestamp."""
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return str(value or "")
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def _visible(value: Any, limit: int = 600) -> str:
    """Upstream-controlled text with invisible characters made visible, and bounded.

    Like `warden.scan.findings.excerpt`, every non-printable character becomes `<U+XXXX>` - a
    zero-width space or a right-to-left override cannot hide part of a poisoned description
    from the admin reviewing it. Unlike `excerpt`, line breaks and tabs survive, because here
    the text is shown in a <pre> block where layout is the point, not in a one-line log field.
    """
    text = str(value if value is not None else "")
    rendered: list[str] = []
    for char in text[:limit]:
        if char in "\n\t":
            rendered.append(char)
        elif char == "\r":
            continue
        elif char.isprintable():
            rendered.append(char)
        else:
            rendered.append(f"<U+{ord(char):04X}>")
    return "".join(rendered) + ("..." if len(text) > limit else "")


def _tone(value: Any) -> str:
    """Badge colour for a decision, reason code, pin status or upstream state."""
    text = str(value or "").lower()
    if text in (
        "allow",
        "allowed",
        "warden_allowed",
        "pinned",
        "up",
        "approved",
        "finished",
        "ok",
        "consumed",
    ):
        return "ok"
    if text.startswith("warden_pending") or text in ("pending", "connecting", "started"):
        return "warn"
    if text.startswith("warden_upstream"):
        return "warn"
    if text.startswith("warden_denied") or text in (
        "deny",
        "denied",
        "quarantined",
        "down",
        "expired",
        "failed",
    ):
        return "bad"
    return "neutral"


def build_environment() -> Environment:
    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"], default_for_string=True, default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["pretty"] = _pretty
    environment.filters["ago"] = _ago
    environment.filters["clock"] = _clock
    environment.filters["visible"] = _visible
    environment.filters["tone"] = _tone
    environment.globals["htmx_url"] = HTMX_URL
    environment.globals["stylesheet"] = STYLESHEET_PATH
    environment.globals["prefix"] = CONSOLE_PREFIX
    environment.globals["nav"] = NAV
    environment.globals["csrf_field"] = CSRF_FIELD
    return environment


# ----------------------------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------------------------

Handler = Callable[..., Awaitable[Response]]


def build_console_routes(deps: ConsoleDeps) -> list[Route]:
    environment = build_environment()
    sessions = deps.sessions

    def render(name: str, *, status: int = 200, **context: Any) -> HTMLResponse:
        defaults: dict[str, Any] = {
            "notice": None,
            "notice_tone": "ok",
            "active": "",
            "user_id": "",
            "roles": (),
            "is_admin": False,
            "csrf_token": "",
        }
        return HTMLResponse(
            environment.get_template(name).render({**defaults, **context}), status_code=status
        )

    def current(request: Request) -> ConsoleSession | None:
        return sessions.get(request.cookies.get(SESSION_COOKIE))

    def base(session: ConsoleSession, active: str) -> dict[str, Any]:
        return {
            "user_id": session.user_id,
            "roles": session.roles,
            "is_admin": session.is_admin,
            "csrf_token": session.csrf_token,
            "active": active,
        }

    # -- guards: every route goes through exactly one of these ------------------------------

    def forbidden_page(session: ConsoleSession, request: Request) -> HTMLResponse:
        logger.warning(
            "console page refused: admin role required",
            extra={"warden": {"principal": session.user_id, "path": request.url.path}},
        )
        return render("forbidden.html", status=403, **base(session, ""))

    def page(*, admin: bool = False) -> Callable[[Handler], Handler]:
        """A full page: the sign-in form when signed out, 403 when the role is not enough."""

        def decorate(handler: Handler) -> Handler:
            async def wrapped(request: Request) -> Response:
                session = current(request)
                if session is None:
                    return render("login.html", error=None)
                if admin and not session.is_admin:
                    return forbidden_page(session, request)
                return await handler(request, session)

            return wrapped

        return decorate

    def fragment(*, admin: bool = False) -> Callable[[Handler], Handler]:
        """An HTMX fragment: 401 when signed out, 403 when the role is not enough."""

        def decorate(handler: Handler) -> Handler:
            async def wrapped(request: Request) -> Response:
                session = current(request)
                if session is None:
                    return _expired()
                if admin and not session.is_admin:
                    return _forbidden_fragment()
                return await handler(request, session)

            return wrapped

        return decorate

    def action(*, admin: bool = False) -> Callable[[Handler], Handler]:
        """A POST: signed in, the right role, *and* this session's CSRF token."""

        def decorate(handler: Handler) -> Handler:
            async def wrapped(request: Request) -> Response:
                session = current(request)
                if session is None:
                    return _expired()
                if admin and not session.is_admin:
                    logger.warning(
                        "console action refused: admin role required",
                        extra={"warden": {"principal": session.user_id, "path": request.url.path}},
                    )
                    return _forbidden_fragment()
                form = await request.form()
                supplied = str(form.get(CSRF_FIELD, ""))
                if not supplied or not hmac.compare_digest(supplied, session.csrf_token):
                    logger.warning(
                        "console action refused: bad CSRF token",
                        extra={"warden": {"principal": session.user_id, "path": request.url.path}},
                    )
                    return HTMLResponse(
                        '<p class="notice bad">Rejected: missing or wrong CSRF token. Reload '
                        "the page and try again.</p>",
                        status_code=403,
                    )
                return await handler(request, session, form)

            return wrapped

        return decorate

    # -- sign in / out -----------------------------------------------------------------------

    async def login(request: Request) -> Response:
        form = await request.form()
        credential = str(form.get("api_key", ""))
        try:
            principal = await deps.api_keys.verify(credential)
        except InvalidApiKey:
            logger.info("console sign-in refused", extra={"warden": {"reason": "bad key"}})
            return render("login.html", status=401, error="That key was not accepted.")
        except Exception:
            logger.exception("console sign-in failed")
            return render("login.html", status=503, error="Sign-in is unavailable right now.")
        token, _session = sessions.create(principal.user_id, tuple(principal.roles))
        response = RedirectResponse(CONSOLE_PREFIX, status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="strict",
            secure=_is_secure_origin(request),
            max_age=SESSION_TTL_SECONDS,
            path=CONSOLE_PREFIX,
        )
        logger.warning(
            "console sign-in",
            extra={"warden": {"principal": principal.user_id, "roles": list(principal.roles)}},
        )
        return response

    @action()
    async def logout(request: Request, session: ConsoleSession, _form: Any) -> Response:
        sessions.destroy(request.cookies.get(SESSION_COOKIE))
        response = RedirectResponse(CONSOLE_PREFIX, status_code=303)
        response.delete_cookie(SESSION_COOKIE, path=CONSOLE_PREFIX)
        return response

    # -- shared lookups ----------------------------------------------------------------------

    def known_roles() -> list[str]:
        return sorted(set(deps.policies.status()["roles"]) | {ADMIN_ROLE})

    def playable_roles(session: ConsoleSession) -> list[str]:
        """An admin may act as any role; anyone else only as a role they hold."""
        if session.is_admin:
            return known_roles()
        return sorted(set(session.roles))

    def visible_for(role: str) -> list[str]:
        definitions = [registered.public_definition() for registered in deps.registry]
        principal = console_principal("console-preview", role)
        return sorted(tool.name for tool in deps.tool_filter(principal, definitions))

    def visible_for_session(session: ConsoleSession) -> list[str]:
        names: set[str] = set()
        for role in session.roles:
            names.update(visible_for(role))
        return sorted(names)

    async def my_requests(session: ConsoleSession) -> tuple[list[dict[str, Any]], list[Any]]:
        pending = [
            row
            for row in await deps.approvals.pending()
            if session.is_admin or row["principal_id"] == session.user_id
        ]
        recent = [
            row
            for row in await deps.approvals.recent(limit=100)
            if row["status"] != "pending"
            and (session.is_admin or row["principal_id"] == session.user_id)
        ]
        return pending, recent[:15]

    # -- overview ----------------------------------------------------------------------------

    async def overview_context(session: ConsoleSession) -> dict[str, Any]:
        filters = AuditFilters() if session.is_admin else AuditFilters(principal_id=session.user_id)
        rows = (await deps.audit.query(filters, limit=OVERVIEW_WINDOW)).rows
        outcomes = [r for r in rows if r.get("event") in ("finished", "denied")]
        by_reason = Counter(str(r.get("reason_code")) for r in outcomes)
        allowed = sum(1 for r in outcomes if r.get("decision") == str(Decision.ALLOW))
        try:
            pending_rows, _recent = await my_requests(session)
            pending: int | None = len(pending_rows)
        except Exception:
            logger.warning("console could not count pending approvals")
            pending = None
        context: dict[str, Any] = {
            "window": len(outcomes),
            "allowed": allowed,
            "denied": len(outcomes) - allowed,
            "by_reason": by_reason.most_common(),
            "activity": outcomes[:12],
            "pending": pending,
            "my_tools": visible_for_session(session),
        }
        if session.is_admin:
            health = sorted(
                (h.as_dict() for h in deps.upstreams.health().values()),
                key=lambda h: str(h["name"]),
            )
            context.update(
                health=health,
                upstreams_up=sum(1 for h in health if h["state"] == "up"),
                tool_count=len(deps.registry),
                quarantined=len(deps.pins.quarantined_names),
                policy=deps.policies.status(),
            )
        return context

    @page()
    async def overview(request: Request, session: ConsoleSession) -> Response:
        return render(
            "overview.html", **base(session, "overview"), **await overview_context(session)
        )

    @fragment()
    async def overview_live(request: Request, session: ConsoleSession) -> Response:
        return render(
            "_overview_live.html", **base(session, "overview"), **await overview_context(session)
        )

    @fragment(admin=True)
    async def audit_verify(request: Request, session: ConsoleSession) -> Response:
        return render("_verify.html", result=await deps.audit.verify())

    # -- tools (admin) -----------------------------------------------------------------------

    async def tools_rows(status: str | None) -> list[dict[str, Any]]:
        pins = await deps.pins.list_pins(status=status)
        servers = {upstream.name: upstream for upstream in deps.servers.upstreams}
        rows = []
        for pin in sorted(pins, key=lambda p: str(p["name"])):
            upstream = servers.get(str(pin["server"]))
            scan = pin.get("scan") or {}
            rows.append(
                {
                    **pin,
                    "exposed": deps.registry.get(str(pin["name"])) is not None,
                    "trusted": bool(upstream.trusted) if upstream else False,
                    "risk": str(upstream.risk_for(str(pin["tool"]))) if upstream else "-",
                    "verdict": scan.get("verdict", "-"),
                    "rules": scan.get("rules") or [],
                }
            )
        return rows

    @page(admin=True)
    async def tools(request: Request, session: ConsoleSession) -> Response:
        status = request.query_params.get("status") or None
        if status not in (None, "pinned", "quarantined"):
            status = None
        return render(
            "tools.html",
            **base(session, "tools"),
            rows=await tools_rows(status),
            status_filter=status or "",
        )

    async def render_tool(
        session: ConsoleSession, name: str, *, notice: str | None = None, tone: str = "ok"
    ) -> HTMLResponse:
        parts = split_namespaced(name)
        pin = await deps.pins.get_pin(*parts) if parts else None
        if parts is None or pin is None:
            return render("missing.html", status=404, **base(session, "tools"), what=name)
        pair = await deps.pins.definitions_for_diff(*parts)
        registered = deps.registry.get(name)
        scan = pin.get("scan") or {}
        return render(
            "tool.html",
            **base(session, "tools"),
            pin=pin,
            diff=diff_definitions(*pair) if pair else [],
            definition=(
                registered.public_definition().model_dump(mode="json", by_alias=True)
                if registered
                else None
            ),
            findings=scan.get("findings") or [],
            verdict=scan.get("verdict", "-"),
            score=scan.get("score"),
            notice=notice,
            notice_tone=tone,
        )

    @page(admin=True)
    async def tool_detail(request: Request, session: ConsoleSession) -> Response:
        return await render_tool(session, request.path_params["name"])

    @action(admin=True)
    async def tool_approve(request: Request, session: ConsoleSession, form: Any) -> Response:
        name = request.path_params["name"]
        parts = split_namespaced(name)
        ok = parts is not None and await deps.pins.approve(*parts, approved_by=session.user_id)
        return await render_tool(
            session,
            name,
            notice=f"{name}: current definition approved and pinned." if ok else "Not found.",
            tone="ok" if ok else "bad",
        )

    @action(admin=True)
    async def tool_quarantine(request: Request, session: ConsoleSession, form: Any) -> Response:
        name = request.path_params["name"]
        parts = split_namespaced(name)
        reason = str(form.get("reason", "")).strip()[:200] or "quarantined from the console"
        ok = parts is not None and await deps.pins.quarantine(
            *parts, by=session.user_id, reason=reason
        )
        return await render_tool(
            session,
            name,
            notice=f"{name} quarantined: it is hidden and refused until approved."
            if ok
            else "Not found.",
            tone="warn" if ok else "bad",
        )

    @action(admin=True)
    async def tools_refresh(request: Request, session: ConsoleSession, form: Any) -> Response:
        await deps.upstreams.refresh_all()
        return render(
            "tools.html",
            **base(session, "tools"),
            rows=await tools_rows(None),
            status_filter="",
            notice="Tool listings re-fetched from every connected upstream and re-pinned.",
        )

    # -- approvals (everyone; deciding is admin-only) ---------------------------------------

    async def approvals_context(session: ConsoleSession) -> dict[str, Any]:
        pending, recent = await my_requests(session)
        return {**base(session, "approvals"), "pending": pending, "recent": recent}

    @page()
    async def approvals_page(request: Request, session: ConsoleSession) -> Response:
        return render("approvals.html", **await approvals_context(session))

    @fragment()
    async def approvals_queue(request: Request, session: ConsoleSession) -> Response:
        return render("_approval_queue.html", **await approvals_context(session))

    @action(admin=True)
    async def approvals_decide(request: Request, session: ConsoleSession, form: Any) -> Response:
        approval_id = str(form.get("approval_id", ""))[:64]
        verb = str(form.get("action", ""))
        reason = str(form.get("reason", "")).strip()[:200] or None
        if verb not in ("approve", "deny"):
            return HTMLResponse('<p class="notice bad">Unknown action.</p>', status_code=400)
        changed, message = await deps.approvals.decide(
            approval_id, approve=verb == "approve", decided_by=session.user_id, reason=reason
        )
        return render(
            "_approval_queue.html",
            status=200 if changed else 409,
            **await approvals_context(session),
            notice=f"{approval_id[:8]}: {message}." if changed else f"Not applied: {message}.",
            notice_tone="ok" if changed else "bad",
        )

    # -- activity / audit (everyone; non-admins see only their own rows) --------------------

    def audit_filters(request: Request, session: ConsoleSession) -> AuditFilters:
        params = request.query_params

        def value(name: str) -> str | None:
            raw = (params.get(name) or "").strip()
            return raw[:200] or None

        return AuditFilters(
            # Forced, not defaulted: a non-admin cannot widen this by editing the URL.
            principal_id=value("principal") if session.is_admin else session.user_id,
            tool=value("tool"),
            decision=value("decision"),
            event=value("event"),
            reason_code=value("reason_code"),
            request_id=value("request_id"),
        )

    @page()
    async def audit_page(request: Request, session: ConsoleSession) -> Response:
        filters = audit_filters(request, session)
        cursor_raw = request.query_params.get("cursor") or ""
        cursor = int(cursor_raw) if cursor_raw.isdigit() else None
        result = await deps.audit.query(filters, cursor=cursor, limit=AUDIT_PAGE_SIZE)
        query = {
            "principal": (filters.principal_id or "") if session.is_admin else "",
            "tool": filters.tool or "",
            "decision": filters.decision or "",
            "event": filters.event or "",
            "reason_code": filters.reason_code or "",
            "request_id": filters.request_id or "",
        }
        return render(
            "audit.html",
            **base(session, "audit"),
            rows=result.rows,
            next_cursor=result.next_cursor,
            query=query,
            query_string=urlencode({k: v for k, v in query.items() if v}),
            decisions=[str(d) for d in Decision],
            events=["started", "finished", "denied"],
            reason_codes=[str(code) for code in ReasonCode],
            first_page=cursor is None,
        )

    @fragment()
    async def audit_detail(request: Request, session: ConsoleSession) -> Response:
        rows = await deps.audit.rows_for_request(request.path_params["request_id"][:64])
        if not session.is_admin:
            rows = [row for row in rows if row.get("principal_id") == session.user_id]
        if not rows:
            return HTMLResponse('<p class="notice bad">No such request.</p>', status_code=404)
        return render("_audit_detail.html", rows=rows)

    @page()
    async def audit_csv(request: Request, session: ConsoleSession) -> Response:
        from warden.admin import _csv_response

        result = await deps.audit.query(audit_filters(request, session), limit=1000)
        return _csv_response(result.rows)

    # -- API keys (admin) --------------------------------------------------------------------

    async def keys_context(session: ConsoleSession, **extra: Any) -> dict[str, Any]:
        keys = [key.as_dict() for key in await deps.api_keys.list_keys()]
        keys.sort(key=lambda k: (k["revoked_at"] is not None, str(k["user_id"])))
        return {
            **base(session, "keys"),
            "keys": keys,
            "role_choices": known_roles(),
            "created": None,
            "form": {"user_id": "", "label": "", "roles": []},
            **extra,
        }

    @page(admin=True)
    async def keys_page(request: Request, session: ConsoleSession) -> Response:
        return render("keys.html", **await keys_context(session))

    @action(admin=True)
    async def keys_create(request: Request, session: ConsoleSession, form: Any) -> Response:
        user_id = str(form.get("user_id", "")).strip()
        label = str(form.get("label", "")).strip()[:120] or None
        roles = sorted({str(role) for role in form.getlist("roles")})
        problem = None
        if not USER_ID_PATTERN.match(user_id):
            problem = "User id: 1-64 characters, letters, digits and . _ @ - only."
        elif not roles:
            problem = "Pick at least one role: a key with no role could never call anything."
        elif not set(roles) <= set(known_roles()):
            problem = "Unknown role."
        if problem:
            return render(
                "keys.html",
                status=400,
                **await keys_context(
                    session, form={"user_id": user_id, "label": label or "", "roles": roles}
                ),
                notice=problem,
                notice_tone="bad",
            )
        generated = await deps.api_keys.create(user_id, roles, label=label)
        logger.warning(
            "API key created from the console",
            extra={
                "warden": {
                    "by": session.user_id,
                    "user": user_id,
                    "roles": roles,
                    "prefix": generated.prefix,
                }
            },
        )
        return render(
            "keys.html",
            **await keys_context(
                session,
                created={
                    "secret": generated.secret,
                    "prefix": generated.prefix,
                    "user_id": user_id,
                    "roles": roles,
                },
            ),
        )

    @action(admin=True)
    async def keys_revoke(request: Request, session: ConsoleSession, form: Any) -> Response:
        prefix = str(form.get("prefix", "")).strip()[:16]
        count = await deps.api_keys.revoke(prefix) if prefix else 0
        logger.warning(
            "API key revoked from the console",
            extra={"warden": {"by": session.user_id, "prefix": prefix, "count": count}},
        )
        return render(
            "keys.html",
            **await keys_context(session),
            notice=(
                f"Revoked the key with prefix {prefix}. It stops working on its next use."
                if count
                else f"No active key has the prefix {prefix}."
            ),
            notice_tone="warn" if count else "bad",
        )

    # -- policy (admin) ----------------------------------------------------------------------

    def policy_context(session: ConsoleSession) -> dict[str, Any]:
        config = deps.policies.policies
        roles = []
        for role_name in sorted(config.roles):
            role = config.roles[role_name]
            roles.append(
                {
                    "name": role_name,
                    "description": role.description,
                    "rules": [
                        {
                            "id": rule.id,
                            "effect": rule.effect,
                            "tools": list(rule.tools),
                            "constraints": [
                                (argument, _constraint_summary(constraint.model_dump()))
                                for argument, constraint in rule.constraints.items()
                            ],
                            "require_approval": rule.require_approval,
                            "risk": str(rule.risk) if rule.risk else None,
                            "description": rule.description,
                        }
                        for rule in role.rules
                    ],
                    "visible": visible_for(role_name),
                }
            )
        return {
            **base(session, "policy"),
            "policy_status": deps.policies.status(),
            "policy_roles": roles,
            "tool_risk": {name: str(risk) for name, risk in config.tool_risk.items()},
        }

    @page(admin=True)
    async def policy_page(request: Request, session: ConsoleSession) -> Response:
        return render("policy.html", **policy_context(session))

    @action(admin=True)
    async def policy_reload(request: Request, session: ConsoleSession, form: Any) -> Response:
        changed, message = deps.policies.reload()
        logger.warning(
            "policy reload from the console",
            extra={"warden": {"by": session.user_id, "changed": changed, "message": message}},
        )
        rejected = message.startswith("rejected")
        return render(
            "policy.html",
            status=409 if rejected else 200,
            **policy_context(session),
            notice=f"Reload: {message}",
            notice_tone="bad" if rejected else ("ok" if changed else "neutral"),
        )

    # -- playground (everyone, within their own roles) --------------------------------------

    @page()
    async def playground(request: Request, session: ConsoleSession) -> Response:
        roles = playable_roles(session)
        if not roles:
            return forbidden_page(session, request)
        asked = request.query_params.get("role")
        default = "editor" if "editor" in roles else roles[0]
        role = asked if asked in roles else default
        visible = visible_for(role)
        all_tools = sorted(registered.name for registered in deps.registry)
        asked_tool = request.query_params.get("tool") or ""
        choices = all_tools if session.is_admin else visible
        chosen = asked_tool if asked_tool in choices else _first_safe_tool(deps, visible)
        return render(
            "playground.html",
            **base(session, "playground"),
            available=deps.pipeline_factory is not None,
            play_roles=roles,
            role=role,
            visible=visible,
            tool_choices=choices,
            chosen=chosen,
            schema=_schema_view(deps.registry, chosen),
            jobs=[_job_view(job) for job in deps.jobs.recent(session.user_id)],
        )

    @fragment()
    async def playground_tool(request: Request, session: ConsoleSession) -> Response:
        name = request.query_params.get("tool", "")[:200]
        if not session.is_admin and name not in visible_for_session(session):
            return render("_tool_schema.html", schema=None)
        return render("_tool_schema.html", schema=_schema_view(deps.registry, name))

    @action()
    async def playground_run(request: Request, session: ConsoleSession, form: Any) -> Response:
        if deps.pipeline_factory is None:
            return HTMLResponse(
                '<p class="notice bad">The MCP endpoint is not mounted here, so there is no '
                "pipeline to run.</p>",
                status_code=503,
            )
        role = str(form.get("role", ""))
        tool = str(form.get("tool", "")).strip()[:200]
        raw = str(form.get("arguments", "") or "{}")
        problem = None
        arguments: Any = None
        if role not in playable_roles(session):
            # Not a role this user holds: refused here, before the pipeline, and logged.
            logger.warning(
                "console playground refused: role not held",
                extra={"warden": {"principal": session.user_id, "role": role[:32]}},
            )
            problem = "You can only run calls as one of your own roles."
        elif not tool:
            problem = "Pick a tool."
        elif len(raw.encode()) > MAX_PLAYGROUND_ARGUMENT_BYTES:
            problem = "The arguments are too large."
        else:
            try:
                arguments = json.loads(raw)
            except json.JSONDecodeError as exc:
                problem = f"The arguments are not valid JSON: {exc.msg} (line {exc.lineno})."
            else:
                if not isinstance(arguments, dict):
                    problem = 'The arguments must be a JSON object, like {"path": "."}.'
        if problem:
            return render("_job.html", status=400, job=None, problem=problem)
        job = start_job(
            deps.jobs,
            deps.pipeline_factory,
            owner=session.user_id,
            tool=tool,
            role=role,
            arguments=arguments,
        )
        return render("_job.html", job=_job_view(job), problem=None)

    @fragment()
    async def playground_job(request: Request, session: ConsoleSession) -> Response:
        job = deps.jobs.get(request.path_params["job_id"][:64], session.user_id)
        if job is None:
            return HTMLResponse('<p class="notice bad">No such call.</p>', status_code=404)
        return render("_job.html", job=_job_view(job), problem=None)

    # -- static ------------------------------------------------------------------------------

    css = (STATIC_DIR / "console.css").read_bytes()

    async def stylesheet(_: Request) -> Response:
        return Response(css, media_type="text/css; charset=utf-8")

    p = CONSOLE_PREFIX
    return [
        Route(STYLESHEET_PATH, stylesheet, methods=["GET"]),
        Route(p, overview, methods=["GET"]),
        Route(f"{p}/login", login, methods=["POST"]),
        Route(f"{p}/logout", logout, methods=["POST"]),
        Route(f"{p}/fragments/overview", overview_live, methods=["GET"]),
        Route(f"{p}/fragments/verify", audit_verify, methods=["GET"]),
        Route(f"{p}/playground", playground, methods=["GET"]),
        Route(f"{p}/playground/run", playground_run, methods=["POST"]),
        Route(f"{p}/fragments/playground/tool", playground_tool, methods=["GET"]),
        Route(f"{p}/fragments/jobs/{{job_id}}", playground_job, methods=["GET"]),
        Route(f"{p}/audit", audit_page, methods=["GET"]),
        Route(f"{p}/audit.csv", audit_csv, methods=["GET"]),
        Route(f"{p}/fragments/audit/{{request_id}}", audit_detail, methods=["GET"]),
        Route(f"{p}/approvals", approvals_page, methods=["GET"]),
        Route(f"{p}/fragments/approvals", approvals_queue, methods=["GET"]),
        Route(f"{p}/approvals/decide", approvals_decide, methods=["POST"]),
        Route(f"{p}/tools", tools, methods=["GET"]),
        Route(f"{p}/tools/refresh", tools_refresh, methods=["POST"]),
        Route(f"{p}/tools/{{name}}", tool_detail, methods=["GET"]),
        Route(f"{p}/tools/{{name}}/approve", tool_approve, methods=["POST"]),
        Route(f"{p}/tools/{{name}}/quarantine", tool_quarantine, methods=["POST"]),
        Route(f"{p}/keys", keys_page, methods=["GET"]),
        Route(f"{p}/keys/create", keys_create, methods=["POST"]),
        Route(f"{p}/keys/revoke", keys_revoke, methods=["POST"]),
        Route(f"{p}/policy", policy_page, methods=["GET"]),
        Route(f"{p}/policy/reload", policy_reload, methods=["POST"]),
    ]


# ----------------------------------------------------------------------------------------------


def _expired() -> HTMLResponse:
    return HTMLResponse(
        '<p class="notice bad">Your session has expired. Reload the page to sign in.</p>',
        status_code=401,
    )


def _forbidden_fragment() -> HTMLResponse:
    return HTMLResponse(
        '<p class="notice bad">This needs the admin role.</p>',
        status_code=403,
    )


def _constraint_summary(constraint: dict[str, Any]) -> str:
    """One readable line for an argument constraint: 'starts with "." · max length 512'."""
    parts: list[str] = []
    labels = (
        ("starts_with", "starts with"),
        ("max_length", "max length"),
        ("min", "min"),
        ("max", "max"),
        ("equals", "equals"),
        ("in_list", "one of"),
        ("regex", "matches"),
    )
    for key, label in labels:
        value = constraint.get(key)
        if value is None:
            continue
        rendered = json.dumps(value, ensure_ascii=False) if isinstance(value, str | list) else value
        parts.append(f"{label} {rendered}")
    if constraint.get("optional"):
        parts.append("optional")
    return " \u00b7 ".join(parts) or "any value"


def _first_safe_tool(deps: ConsoleDeps, visible: list[str]) -> str:
    """The playground's default tool: a read-only one, so the first click cannot delete anything."""
    servers = {upstream.name: upstream for upstream in deps.servers.upstreams}
    for name in visible:
        registered = deps.registry.get(name)
        if registered is None:
            continue
        upstream = servers.get(registered.upstream)
        if upstream is not None and str(upstream.risk_for(registered.upstream_tool)) == "read":
            return name
    return visible[0] if visible else ""


def _schema_view(registry: ToolRegistry, name: str) -> dict[str, Any] | None:
    registered = registry.get(name) if name else None
    if registered is None:
        return None
    schema = registered.definition.input_schema
    required = list(schema.get("required") or []) if isinstance(schema, dict) else []
    return {
        "name": registered.name,
        "description": registered.definition.description or "",
        "schema": schema,
        "suggested": _pretty(suggested_arguments(schema)),
        "required": required,
    }


def _job_view(job: Any) -> dict[str, Any]:
    return {
        "id": job.id,
        "tool": job.tool,
        "role": job.role,
        "arguments": job.arguments,
        "done": job.done,
        "elapsed": round(job.elapsed_seconds, 1),
        "elapsed_label": (
            f"{job.elapsed_seconds * 1000:.0f} ms"
            if job.elapsed_seconds < 1
            else f"{job.elapsed_seconds:.1f} s"
        ),
        "started_at": job.started_at,
        "outcome": job.outcome(),
    }


__all__ = [
    "ADMIN_ROLE",
    "CONSOLE_PREFIX",
    "CSRF_FIELD",
    "SESSION_COOKIE",
    "ConsoleDeps",
    "ConsoleSession",
    "ConsoleSessions",
    "build_console_routes",
    "build_environment",
]
