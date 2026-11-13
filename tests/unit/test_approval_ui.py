"""The approval UI: sign-in, CSRF, cookie flags, and escaping of hostile values."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from warden.approval.store import ApprovalStore
from warden.approval.web import (
    CSRF_FIELD,
    SESSION_COOKIE,
    SessionStore,
    build_approval_routes,
)
from warden.auth.api_keys import ApiKeyStore
from warden.db.engine import Database

pytestmark = pytest.mark.unit

HOSTILE = '<script>alert("xss")</script>'


@pytest.fixture
def approvals(database: Database) -> ApprovalStore:
    return ApprovalStore(database, expiry_seconds=300.0)


@pytest.fixture
def sessions() -> SessionStore:
    return SessionStore()


@pytest.fixture
def app(approvals: ApprovalStore, api_keys: ApiKeyStore, sessions: SessionStore) -> Starlette:
    return Starlette(
        routes=build_approval_routes(approvals=approvals, api_keys=api_keys, sessions=sessions)
    )


async def admin_key(api_keys: ApiKeyStore) -> str:
    return (await api_keys.create("admin-user", ["admin"])).secret


async def signed_in(app: Starlette, api_keys: ApiKeyStore) -> TestClient:
    secret = await admin_key(api_keys)
    client = TestClient(app, base_url="http://testserver")
    response = client.post("/approvals/login", data={"api_key": secret}, follow_redirects=False)
    assert response.status_code == 303, response.text
    return client


async def pending_approval(approvals: ApprovalStore, **overrides: Any) -> str:
    fields: dict[str, Any] = {
        "principal_id": "editor-user",
        "tool": "files__delete_file",
        "args_redacted": {"path": "notes/a.md"},
        "args_sha256": "a" * 64,
        "request_id": "req-1",
        "risk": "destructive",
    }
    fields.update(overrides)
    return (await approvals.create(**fields)).id


def csrf_of(client: TestClient) -> str:
    page = client.get("/approvals")
    assert page.status_code == 200
    marker = f'name="{CSRF_FIELD}" value="'
    start = page.text.index(marker) + len(marker)
    return page.text[start : page.text.index('"', start)]


# -- signing in --------------------------------------------------------------------------------


def test_the_page_asks_for_a_key_when_not_signed_in(app: Starlette) -> None:
    with TestClient(app) as client:
        response = client.get("/approvals")
    assert response.status_code == 200
    assert "Admin API key" in response.text
    assert 'type="password"' in response.text, "the key field must not be a visible text input"


async def test_a_wrong_key_is_refused(app: Starlette, api_keys: ApiKeyStore) -> None:
    with TestClient(app) as client:
        response = client.post("/approvals/login", data={"api_key": "wdn_" + "x" * 32})
    assert response.status_code == 401
    assert "not accepted" in response.text


async def test_a_non_admin_key_is_refused(app: Starlette, api_keys: ApiKeyStore) -> None:
    """Authentication is not authorisation, here as everywhere else."""
    editor = (await api_keys.create("editor-user", ["editor"])).secret
    with TestClient(app) as client:
        response = client.post("/approvals/login", data={"api_key": editor})
    assert response.status_code == 401
    assert "admin role is required" in response.text


async def test_a_valid_admin_key_sets_a_hardened_session_cookie(
    app: Starlette, api_keys: ApiKeyStore
) -> None:
    secret = await admin_key(api_keys)
    with TestClient(app) as client:
        response = client.post("/approvals/login", data={"api_key": secret}, follow_redirects=False)
    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    assert SESSION_COOKIE in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie.replace("samesite", "SameSite")
    assert "Path=/approvals" in cookie
    assert secret not in cookie, "the credential must not become the session token"


async def test_the_cookie_is_secure_over_https(app: Starlette, api_keys: ApiKeyStore) -> None:
    secret = await admin_key(api_keys)
    with TestClient(app, base_url="https://warden.example") as client:
        response = client.post("/approvals/login", data={"api_key": secret}, follow_redirects=False)
    assert "Secure" in response.headers["set-cookie"]


async def test_the_cookie_is_not_secure_over_plain_localhost(
    app: Starlette, api_keys: ApiKeyStore
) -> None:
    """Otherwise the cookie is unusable during local development."""
    secret = await admin_key(api_keys)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        response = client.post("/approvals/login", data={"api_key": secret}, follow_redirects=False)
    assert "Secure" not in response.headers["set-cookie"]


async def test_a_forwarded_https_header_makes_the_cookie_secure(
    app: Starlette, api_keys: ApiKeyStore
) -> None:
    secret = await admin_key(api_keys)
    with TestClient(app) as client:
        response = client.post(
            "/approvals/login",
            data={"api_key": secret},
            headers={"x-forwarded-proto": "https"},
            follow_redirects=False,
        )
    assert "Secure" in response.headers["set-cookie"]


async def test_the_key_never_appears_in_the_page(app: Starlette, api_keys: ApiKeyStore) -> None:
    secret = await admin_key(api_keys)
    client = await signed_in(app, api_keys)
    page = client.get("/approvals")
    assert secret not in page.text
    assert "wdn_" not in page.text


async def test_signing_out_destroys_the_session(
    app: Starlette, api_keys: ApiKeyStore, sessions: SessionStore
) -> None:
    client = await signed_in(app, api_keys)
    assert len(sessions) == 1
    token = csrf_of(client)
    client.post("/approvals/logout", data={CSRF_FIELD: token}, follow_redirects=False)
    assert len(sessions) == 0
    assert "Admin API key" in client.get("/approvals").text


# -- CSRF --------------------------------------------------------------------------------------


async def test_a_post_without_a_csrf_token_is_refused(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    approval_id = await pending_approval(approvals)
    client = await signed_in(app, api_keys)
    response = client.post(
        "/approvals/decide", data={"approval_id": approval_id, "action": "approve"}
    )
    assert response.status_code == 403
    assert "CSRF" in response.text
    row = await approvals.get(approval_id)
    assert row is not None and row["status"] == "pending"


async def test_a_post_with_a_wrong_csrf_token_is_refused(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    approval_id = await pending_approval(approvals)
    client = await signed_in(app, api_keys)
    response = client.post(
        "/approvals/decide",
        data={
            CSRF_FIELD: "not-the-token",
            "approval_id": approval_id,
            "action": "approve",
        },
    )
    assert response.status_code == 403
    row = await approvals.get(approval_id)
    assert row is not None and row["status"] == "pending"


async def test_one_sessions_token_does_not_work_for_another(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    approval_id = await pending_approval(approvals)
    first = await signed_in(app, api_keys)
    stolen = csrf_of(first)
    second = await signed_in(app, api_keys)
    response = second.post(
        "/approvals/decide",
        data={CSRF_FIELD: stolen, "approval_id": approval_id, "action": "approve"},
    )
    assert response.status_code == 403


async def test_deciding_without_a_session_is_refused(
    app: Starlette, approvals: ApprovalStore
) -> None:
    approval_id = await pending_approval(approvals)
    with TestClient(app) as client:
        response = client.post(
            "/approvals/decide",
            data={CSRF_FIELD: "anything", "approval_id": approval_id, "action": "approve"},
        )
    assert response.status_code == 401
    assert (await approvals.get(approval_id))["status"] == "pending"  # type: ignore[index]


async def test_the_queue_fragment_needs_a_session(app: Starlette) -> None:
    with TestClient(app) as client:
        assert client.get("/approvals/queue").status_code == 401


# -- deciding ----------------------------------------------------------------------------------


async def test_approving_through_the_ui(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    approval_id = await pending_approval(approvals)
    client = await signed_in(app, api_keys)
    response = client.post(
        "/approvals/decide",
        data={
            CSRF_FIELD: csrf_of(client),
            "approval_id": approval_id,
            "action": "approve",
            "reason": "reviewed the path",
        },
    )
    assert response.status_code == 200
    row = await approvals.get(approval_id)
    assert row is not None
    assert row["status"] == "approved"
    assert row["decided_by"] == "admin-user"
    assert row["decision_reason"] == "reviewed the path"


async def test_denying_through_the_ui(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    approval_id = await pending_approval(approvals)
    client = await signed_in(app, api_keys)
    client.post(
        "/approvals/decide",
        data={CSRF_FIELD: csrf_of(client), "approval_id": approval_id, "action": "deny"},
    )
    assert (await approvals.get(approval_id))["status"] == "denied"  # type: ignore[index]


async def test_an_unknown_action_is_refused(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    approval_id = await pending_approval(approvals)
    client = await signed_in(app, api_keys)
    response = client.post(
        "/approvals/decide",
        data={CSRF_FIELD: csrf_of(client), "approval_id": approval_id, "action": "maybe"},
    )
    assert response.status_code == 400
    assert (await approvals.get(approval_id))["status"] == "pending"  # type: ignore[index]


async def test_deciding_twice_reports_a_conflict(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    approval_id = await pending_approval(approvals)
    client = await signed_in(app, api_keys)
    token = csrf_of(client)
    first = client.post(
        "/approvals/decide",
        data={CSRF_FIELD: token, "approval_id": approval_id, "action": "approve"},
    )
    second = client.post(
        "/approvals/decide",
        data={CSRF_FIELD: token, "approval_id": approval_id, "action": "deny"},
    )
    assert first.status_code == 200
    assert second.status_code == 409
    assert "Not applied" in second.text


async def test_the_requester_is_shown_that_they_cannot_self_approve(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    await pending_approval(approvals, principal_id="admin-user")
    client = await signed_in(app, api_keys)
    page = client.get("/approvals")
    assert "cannot approve it" in page.text
    assert "Approve</button>" not in page.text


async def test_self_approval_is_refused_even_if_the_form_is_forged(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    """Hiding the button is a courtesy; the store is what enforces it."""
    approval_id = await pending_approval(approvals, principal_id="admin-user")
    client = await signed_in(app, api_keys)
    response = client.post(
        "/approvals/decide",
        data={CSRF_FIELD: csrf_of(client), "approval_id": approval_id, "action": "approve"},
    )
    assert response.status_code == 409
    assert (await approvals.get(approval_id))["status"] == "pending"  # type: ignore[index]


# -- escaping ----------------------------------------------------------------------------------


async def test_hostile_argument_values_are_escaped(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    """Everything on this page comes from an attacker: tool name, arguments, scan evidence."""
    await pending_approval(
        approvals,
        args_redacted={"path": HOSTILE, "note": "<img src=x onerror=alert(1)>"},
        scan_flags={"dlp": {"rules": ["<b>bold</b>"]}},
    )
    client = await signed_in(app, api_keys)
    page = client.get("/approvals")
    assert page.status_code == 200
    assert HOSTILE not in page.text
    assert "<img src=x" not in page.text
    assert "<b>bold</b>" not in page.text
    assert "&lt;script&gt;" in page.text, "the value must still be visible, just escaped"


async def test_a_hostile_tool_name_is_escaped(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    await pending_approval(approvals, tool="files__<script>x</script>")
    client = await signed_in(app, api_keys)
    page = client.get("/approvals")
    assert "<script>x</script>" not in page.text


async def test_a_hostile_decision_reason_is_escaped(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    approval_id = await pending_approval(approvals)
    client = await signed_in(app, api_keys)
    client.post(
        "/approvals/decide",
        data={
            CSRF_FIELD: csrf_of(client),
            "approval_id": approval_id,
            "action": "deny",
            "reason": HOSTILE,
        },
    )
    page = client.get("/approvals")
    assert HOSTILE not in page.text


async def test_no_template_uses_the_safe_filter() -> None:
    """A single `|safe` anywhere would undo the autoescaping the rest of this relies on."""
    from warden.approval.web import TEMPLATE_DIR

    for template in TEMPLATE_DIR.glob("*.html"):
        body = template.read_text(encoding="utf-8")
        assert "|safe" not in body, template.name
        assert "| safe" not in body, template.name
        assert "autoescape false" not in body, template.name


async def test_the_page_lists_what_an_approver_needs(
    app: Starlette, api_keys: ApiKeyStore, approvals: ApprovalStore
) -> None:
    await pending_approval(approvals)
    client = await signed_in(app, api_keys)
    page = client.get("/approvals").text
    assert "files__delete_file" in page
    assert "editor-user" in page, "who asked"
    assert "destructive" in page, "how risky"
    assert "notes/a.md" in page, "what arguments"
    assert "expires" in page, "how long is left"


async def test_an_empty_queue_says_so(app: Starlette, api_keys: ApiKeyStore) -> None:
    client = await signed_in(app, api_keys)
    assert "Nothing is waiting" in client.get("/approvals").text


# -- sessions ----------------------------------------------------------------------------------


def test_an_expired_session_is_not_accepted(sessions: SessionStore) -> None:
    token, session = sessions.create("admin-user")
    assert sessions.get(token) is session
    session.created_at -= 10 * 60 * 60
    assert sessions.get(token) is None
    assert len(sessions) == 0


def test_an_unknown_session_token_is_not_accepted(sessions: SessionStore) -> None:
    assert sessions.get("made-up") is None
    assert sessions.get(None) is None


def test_session_tokens_and_csrf_tokens_differ(sessions: SessionStore) -> None:
    token, session = sessions.create("admin-user")
    assert token != session.csrf_token
    other_token, other = sessions.create("admin-user")
    assert token != other_token
    assert session.csrf_token != other.csrf_token
