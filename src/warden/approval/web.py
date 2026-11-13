"""The approval UI: a small HTMX page an admin signs into with an API key.

Three things carry the security of this page, and each is boring on purpose:

* **Session cookies, not credentials in the page.** The admin posts their API key once; the
  response sets an opaque session cookie that is `HttpOnly`, `SameSite=Strict`, and `Secure`
  whenever the request did not come from localhost. The key never appears in a form, a URL or
  the DOM.
* **A CSRF token on every POST.** `SameSite=Strict` already stops the cross-site case in modern
  browsers, and the token is the belt to that braces: it is bound to the session, compared with
  `compare_digest`, and a POST without it is refused with 403 rather than silently ignored.
* **Jinja autoescaping, and nothing rendered as HTML.** Every value on the page comes from an
  attacker: the tool name, the arguments, the scan evidence. Autoescaping is on, no template
  uses `|safe`, and a test puts `<script>` in an argument and asserts it comes back escaped.

Sessions live in memory. That is a deliberate limit, not an oversight: a single-node approval
UI is in keeping with the rest of the phase, and the consequence - a restart logs admins out -
is the safe direction.
"""

from __future__ import annotations

import hmac
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from warden.approval.store import ApprovalStore
from warden.auth.api_keys import ApiKeyStore, InvalidApiKey
from warden.logging import get_logger

logger = get_logger(__name__)

SESSION_COOKIE: Final = "warden_approvals_session"
CSRF_FIELD: Final = "csrf_token"
SESSION_TTL_SECONDS: Final = 8 * 60 * 60
ADMIN_ROLE: Final = "admin"
TEMPLATE_DIR: Final = Path(__file__).parent / "templates"


@dataclass(slots=True)
class Session:
    """One signed-in admin."""

    user_id: str
    csrf_token: str
    created_at: float = field(default_factory=time.time)

    @property
    def expired(self) -> bool:
        return time.time() - self.created_at > SESSION_TTL_SECONDS


class SessionStore:
    """In-memory sessions, keyed by an opaque token."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def create(self, user_id: str) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        session = Session(user_id=user_id, csrf_token=secrets.token_urlsafe(32))
        self._sessions[token] = session
        return token, session

    def get(self, token: str | None) -> Session | None:
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


def build_environment() -> Environment:
    """Jinja with autoescaping on for HTML. Every value here is attacker-controlled."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(default_for_string=True, default=True),
        undefined=__import__("jinja2").StrictUndefined,
    )


def _is_secure_origin(request: Request) -> bool:
    """True when the browser spoke https, so the cookie should be `Secure`.

    Checked rather than assumed: setting `Secure` on a plain-http localhost session would make
    the cookie unusable during development, and *not* setting it in production would let the
    session travel in clear.
    """
    forwarded = request.headers.get("x-forwarded-proto", "")
    if forwarded:
        return forwarded.split(",")[0].strip() == "https"
    return request.url.scheme == "https"


def _set_session_cookie(response: Response, token: str, *, secure: bool) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=secure,
        max_age=SESSION_TTL_SECONDS,
        path="/approvals",
    )


def build_approval_routes(
    *,
    approvals: ApprovalStore,
    api_keys: ApiKeyStore,
    sessions: SessionStore | None = None,
) -> list[Route]:
    """The /approvals page and its two POST endpoints."""
    store = sessions if sessions is not None else SessionStore()
    environment = build_environment()

    def render(name: str, **context: Any) -> str:
        # csrf_field is injected rather than hard-coded in the templates, so the field name
        # lives in exactly one place. `notice` defaults to None because the environment uses
        # StrictUndefined - which catches a mistyped variable name, and is worth keeping.
        defaults: dict[str, Any] = {"csrf_field": CSRF_FIELD, "notice": None}
        return environment.get_template(name).render({**defaults, **context})

    def current(request: Request) -> Session | None:
        return store.get(request.cookies.get(SESSION_COOKIE))

    async def login_page(request: Request, error: str | None = None) -> Response:
        return HTMLResponse(
            render("login.html", error=error),
            status_code=401 if error else 200,
        )

    async def index(request: Request) -> Response:
        session = current(request)
        if session is None:
            return await login_page(request)
        pending = await approvals.pending()
        recent = await approvals.recent(limit=20)
        return HTMLResponse(
            render(
                "approvals.html",
                user_id=session.user_id,
                csrf_token=session.csrf_token,
                pending=pending,
                recent=[row for row in recent if row["status"] != "pending"][:10],
                now=time.time(),
            )
        )

    async def queue_fragment(request: Request) -> Response:
        """The pending list on its own, for HTMX to poll."""
        session = current(request)
        if session is None:
            return HTMLResponse("<p>Your session has expired. Reload to sign in.</p>", 401)
        return HTMLResponse(
            render(
                "_queue.html",
                csrf_token=session.csrf_token,
                pending=await approvals.pending(),
                user_id=session.user_id,
            )
        )

    async def login(request: Request) -> Response:
        form = await request.form()
        credential = str(form.get("api_key", ""))
        try:
            principal = await api_keys.verify(credential)
        except InvalidApiKey:
            logger.info("approval UI sign-in refused", extra={"warden": {"reason": "bad key"}})
            return await login_page(request, error="That credential was not accepted.")
        except Exception:
            logger.exception("approval UI sign-in failed")
            return await login_page(request, error="Authentication is unavailable.")
        if not principal.has_role(ADMIN_ROLE):
            logger.warning(
                "approval UI sign-in refused",
                extra={"warden": {"principal": principal.user_id, "reason": "not admin"}},
            )
            # No quotes in the message: the page autoescapes, so a quoted role name comes
            # out as &#39;admin&#39; and reads badly.
            return await login_page(
                request, error=f"The {ADMIN_ROLE} role is required to approve calls."
            )
        token, _session = store.create(principal.user_id)
        response = RedirectResponse("/approvals", status_code=303)
        _set_session_cookie(response, token, secure=_is_secure_origin(request))
        logger.warning("approval UI sign-in", extra={"warden": {"principal": principal.user_id}})
        return response

    async def logout(request: Request) -> Response:
        store.destroy(request.cookies.get(SESSION_COOKIE))
        response = RedirectResponse("/approvals", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/approvals")
        return response

    async def decide(request: Request) -> Response:
        session = current(request)
        if session is None:
            return HTMLResponse("<p>Your session has expired. Reload to sign in.</p>", 401)
        form = await request.form()
        supplied = str(form.get(CSRF_FIELD, ""))
        if not supplied or not hmac.compare_digest(supplied, session.csrf_token):
            logger.warning(
                "approval decision refused: bad CSRF token",
                extra={"warden": {"principal": session.user_id}},
            )
            return HTMLResponse("<p>Rejected: missing or wrong CSRF token.</p>", 403)

        approval_id = str(form.get("approval_id", ""))
        action = str(form.get("action", ""))
        reason = str(form.get("reason", "")).strip() or None
        if action not in ("approve", "deny"):
            return HTMLResponse("<p>Rejected: unknown action.</p>", 400)

        changed, message = await approvals.decide(
            approval_id,
            approve=action == "approve",
            decided_by=session.user_id,
            reason=reason,
        )
        if not changed:
            return HTMLResponse(
                render(
                    "_queue.html",
                    csrf_token=session.csrf_token,
                    pending=await approvals.pending(),
                    user_id=session.user_id,
                    notice=f"Not applied: {message}.",
                ),
                status_code=409,
            )
        return HTMLResponse(
            render(
                "_queue.html",
                csrf_token=session.csrf_token,
                pending=await approvals.pending(),
                user_id=session.user_id,
                notice=f"{approval_id[:8]} {message}.",
            )
        )

    return [
        Route("/approvals", index, methods=["GET"]),
        Route("/approvals/queue", queue_fragment, methods=["GET"]),
        Route("/approvals/login", login, methods=["POST"]),
        Route("/approvals/logout", logout, methods=["POST"]),
        Route("/approvals/decide", decide, methods=["POST"]),
    ]


Handler = Callable[[Request], Awaitable[Response]]

__all__ = [
    "ADMIN_ROLE",
    "CSRF_FIELD",
    "SESSION_COOKIE",
    "SESSION_TTL_SECONDS",
    "Session",
    "SessionStore",
    "build_approval_routes",
    "build_environment",
]
