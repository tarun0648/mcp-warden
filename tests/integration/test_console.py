"""The console, end to end: real gateway, real keys for each role, real HTTP.

Two things are tested hardest, because they are what a UI most often gets wrong:

* **authorization is enforced on the server, per route.** A reader is not just shown fewer
  links; every admin page, fragment and action refuses them with 403 and changes nothing.
* **the playground is the real pipeline.** A call made from the console is decided, audited
  and held for approval exactly as an MCP client's would be.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.helpers import running_gateway

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

#: Approvals resolve quickly here, so a destructive call comes back pending in under a second.
QUICK_APPROVALS = {"approval": {"wait_seconds": 0.3, "expiry_seconds": 300.0}}

ADMIN_PAGES = ["/console/tools", "/console/keys", "/console/policy"]
EVERYONE_PAGES = ["/console", "/console/playground", "/console/audit", "/console/approvals"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@contextmanager
def signed_in(gateway: Any, role: str) -> Iterator[httpx.Client]:
    """An HTTP client holding a console session for the key minted for `role`."""
    with httpx.Client(base_url=gateway.url, timeout=30.0, follow_redirects=False) as client:
        response = client.post("/console/login", data={"api_key": gateway.keys[role]})
        assert response.status_code == 303, response.text[:300]
        yield client


def csrf(client: httpx.Client, path: str = "/console") -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).text)
    assert match, "no CSRF token on the page"
    return match.group(1)


def run_call(
    client: httpx.Client, role: str, tool: str, arguments: str = "{}", *, timeout: float = 20.0
) -> str:
    """Run a playground call and return the finished result fragment."""
    response = client.post(
        "/console/playground/run",
        data={"csrf_token": csrf(client), "role": role, "tool": tool, "arguments": arguments},
    )
    assert response.status_code == 200, response.text[:400]
    match = re.search(r'/console/fragments/jobs/([A-Za-z0-9_-]+)"', response.text)
    if match is None:
        return response.text  # finished before the first render
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        fragment = client.get(f"/console/fragments/jobs/{match.group(1)}")
        assert fragment.status_code == 200
        if "every 1s" not in fragment.text:
            return fragment.text
        time.sleep(0.2)
    raise AssertionError("the playground call did not finish")


# -- signed out --------------------------------------------------------------------------------


async def test_every_page_shows_the_sign_in_form_and_no_data_when_signed_out(
    tmp_path: Path,
) -> None:
    with running_gateway(tmp_path) as gateway:
        for path in EVERYONE_PAGES + ADMIN_PAGES:
            response = httpx.get(gateway.url + path, timeout=20)
            assert response.status_code == 200, path
            assert "Sign in to the console" in response.text, path
            assert "csrf_token" not in response.text, path


async def test_fragments_and_actions_refuse_when_signed_out(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        for path in ["/console/fragments/overview", "/console/fragments/verify"]:
            assert httpx.get(gateway.url + path, timeout=20).status_code == 401, path
        for path in ["/console/keys/create", "/console/policy/reload", "/console/playground/run"]:
            assert httpx.post(gateway.url + path, data={}, timeout=20).status_code == 401, path


async def test_a_wrong_key_is_refused(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        response = httpx.post(
            gateway.url + "/console/login", data={"api_key": "wdn_not-a-real-key"}, timeout=20
        )
    assert response.status_code == 401
    assert "not accepted" in response.text
    assert "set-cookie" not in response.headers


async def test_the_session_cookie_is_hardened_and_scoped(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        response = httpx.post(
            gateway.url + "/console/login", data={"api_key": gateway.keys["reader"]}, timeout=20
        )
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie or "SameSite=Strict" in cookie
    assert "Path=/console" in cookie


async def test_the_key_never_appears_in_any_page(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as client:
        secret = gateway.keys["admin"]
        for path in EVERYONE_PAGES + ADMIN_PAGES:
            assert secret not in client.get(path).text, path


# -- every role can sign in ------------------------------------------------------------------


@pytest.mark.parametrize("role", ["admin", "editor", "reader"])
async def test_every_role_can_sign_in_and_use_the_shared_pages(role: str, tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, role) as client:
        for path in EVERYONE_PAGES:
            response = client.get(path)
            assert response.status_code == 200, (role, path)
            assert f"{role}-user" in response.text, (role, path)


async def test_admin_can_open_every_page(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as client:
        for path in EVERYONE_PAGES + ADMIN_PAGES + ["/console/tools/files__read_file"]:
            assert client.get(path).status_code == 200, path
        assert client.get("/console/fragments/overview").status_code == 200
        verify = client.get("/console/fragments/verify")
        assert verify.status_code == 200
        assert "Chain intact" in verify.text


# -- role enforcement ------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["editor", "reader"])
async def test_admin_pages_refuse_other_roles_on_the_server(role: str, tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, role) as client:
        for path in [*ADMIN_PAGES, "/console/tools/files__read_file"]:
            response = client.get(path)
            assert response.status_code == 403, (role, path)
            assert "Admins only" in response.text
        assert client.get("/console/fragments/verify").status_code == 403


@pytest.mark.parametrize("role", ["editor", "reader"])
async def test_admin_actions_refuse_other_roles_and_change_nothing(
    role: str, tmp_path: Path
) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, role) as client:
        token = csrf(client)
        attempts = {
            "/console/keys/create": {"user_id": "mallory", "roles": "admin"},
            "/console/keys/revoke": {"prefix": "anything"},
            "/console/policy/reload": {},
            "/console/tools/refresh": {},
            "/console/tools/files__read_file/quarantine": {"reason": "x"},
            "/console/tools/files__read_file/approve": {},
            "/console/approvals/decide": {"approval_id": "x", "action": "approve"},
        }
        for path, data in attempts.items():
            response = client.post(path, data={"csrf_token": token, **data})
            assert response.status_code == 403, (role, path)
    with running_gateway(tmp_path / "again") as fresh, signed_in(fresh, "admin") as admin:
        assert "mallory" not in admin.get("/console/keys").text


async def test_navigation_hides_admin_sections_from_other_roles(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        with signed_in(gateway, "reader") as client:
            page = client.get("/console").text
        assert 'href="/console/keys"' not in page
        assert 'href="/console/policy"' not in page
        with signed_in(gateway, "admin") as client:
            page = client.get("/console").text
        assert 'href="/console/keys"' in page
        assert 'href="/console/policy"' in page


# -- CSRF ------------------------------------------------------------------------------------


async def test_a_post_without_the_csrf_token_is_refused(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as client:
        response = client.post("/console/keys/create", data={"user_id": "x", "roles": "reader"})
        assert response.status_code == 403
        assert "CSRF" in response.text
        assert 'class="mono wrap-anywhere">x<' not in client.get("/console/keys").text


async def test_another_sessions_csrf_token_does_not_work(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        with signed_in(gateway, "admin") as first:
            stolen = csrf(first)
        with signed_in(gateway, "admin") as second:
            response = second.post(
                "/console/keys/create",
                data={"csrf_token": stolen, "user_id": "x", "roles": "reader"},
            )
        assert response.status_code == 403


# -- playground: the real pipeline -----------------------------------------------------------


async def test_an_allowed_call_runs_and_returns_the_upstream_result(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "reader") as client:
        result = run_call(client, "reader", "notes_db__list_notes", '{"limit": 2}')
    assert "Allowed" in result
    assert "WARDEN_ALLOWED" in result or "allowed" in result.lower()
    assert "notes" in result


async def test_a_traversal_is_refused_by_policy_and_never_forwarded(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "reader") as client:
        result = run_call(client, "reader", "files__read_file", '{"path": "../../etc/passwd"}')
    assert "Refused" in result
    assert "WARDEN_DENIED:policy" in result
    assert "never left the gateway" in result


async def test_defaults_are_filled_and_shown(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "editor") as client:
        result = run_call(client, "editor", "files__list_files", "{}")
    assert "Allowed" in result
    assert "Defaults filled" in result


async def test_a_role_you_do_not_hold_is_refused_before_the_pipeline(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "reader") as client:
        response = client.post(
            "/console/playground/run",
            data={
                "csrf_token": csrf(client),
                "role": "admin",
                "tool": "files__delete_file",
                "arguments": '{"path": "x"}',
            },
        )
    assert response.status_code == 400
    assert "your own roles" in response.text


async def test_an_admin_can_act_as_another_role_and_is_refused_as_that_role(
    tmp_path: Path,
) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as client:
        result = run_call(client, "reader", "files__delete_file", '{"path": "x.md"}')
    assert "WARDEN_DENIED:policy" in result


@pytest.mark.parametrize("arguments", ["not json", "[1, 2]", '"text"'])
async def test_bad_arguments_are_explained(arguments: str, tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "editor") as client:
        response = client.post(
            "/console/playground/run",
            data={
                "csrf_token": csrf(client),
                "role": "editor",
                "tool": "files__list_files",
                "arguments": arguments,
            },
        )
    assert response.status_code == 400
    assert "JSON" in response.text


async def test_playground_calls_are_audited_as_console_calls(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as client:
        run_call(client, "editor", "notes_db__list_notes", "{}")
        page = client.get("/console/audit?tool=notes_db__list_notes").text
    assert "admin-user" in page
    assert ">console<" in page


async def test_a_destructive_call_waits_for_approval_and_shows_in_the_queue(
    tmp_path: Path,
) -> None:
    with (
        running_gateway(tmp_path, gateway_overrides=QUICK_APPROVALS) as gateway,
        signed_in(gateway, "editor") as editor,
    ):
        editor.post(
            "/console/playground/run",
            data={
                "csrf_token": csrf(editor),
                "role": "editor",
                "tool": "files__write_file",
                "arguments": '{"path": "doomed.md", "content": "x"}',
            },
        )
        result = run_call(editor, "editor", "files__delete_file", '{"path": "doomed.md"}')
        assert "WARDEN_PENDING:approval" in result
        assert "files__delete_file" in editor.get("/console/approvals").text
        with signed_in(gateway, "reader") as reader:
            assert "files__delete_file" not in reader.get("/console/approvals").text
        with signed_in(gateway, "admin") as admin:
            queue = admin.get("/console/approvals").text
            assert 'value="approve"' in queue
            approval_id = re.search(r'name="approval_id" value="([^"]+)"', queue)
            assert approval_id
            decided = admin.post(
                "/console/approvals/decide",
                data={
                    "csrf_token": csrf(admin, "/console/approvals"),
                    "approval_id": approval_id.group(1),
                    "action": "approve",
                },
            )
            assert decided.status_code == 200
        retried = run_call(editor, "editor", "files__delete_file", '{"path": "doomed.md"}')
    assert "Allowed" in retried


async def test_the_requester_is_not_offered_a_way_to_approve_their_own_call(
    tmp_path: Path,
) -> None:
    with (
        running_gateway(tmp_path, gateway_overrides=QUICK_APPROVALS) as gateway,
        signed_in(gateway, "admin") as admin,
    ):
        run_call(admin, "editor", "files__delete_file", '{"path": "doomed.md"}')
        queue = admin.get("/console/approvals").text
    assert "another admin has to decide" in queue
    assert 'value="approve"' not in queue


async def test_jobs_belong_to_the_user_who_started_them(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        with signed_in(gateway, "editor") as editor:
            response = editor.post(
                "/console/playground/run",
                data={
                    "csrf_token": csrf(editor),
                    "role": "editor",
                    "tool": "notes_db__list_notes",
                    "arguments": "{}",
                },
            )
            job = re.search(r"/console/fragments/jobs/([A-Za-z0-9_-]+)", response.text)
            assert job
        with signed_in(gateway, "reader") as reader:
            assert reader.get(f"/console/fragments/jobs/{job.group(1)}").status_code == 404


# -- activity: non-admins see only their own rows -------------------------------------------


async def test_a_reader_sees_only_their_own_audit_rows_whatever_the_url_says(
    tmp_path: Path,
) -> None:
    with running_gateway(tmp_path) as gateway:
        with signed_in(gateway, "admin") as admin:
            run_call(admin, "admin", "notes_db__list_notes", "{}")
            admin_rows = admin.get("/console/audit?principal=admin-user").text
            request_id = re.search(r"/console/fragments/audit/([0-9a-f]+)", admin_rows)
            assert request_id
        with signed_in(gateway, "reader") as reader:
            run_call(reader, "reader", "notes_db__list_notes", "{}")
            forced = reader.get("/console/audit?principal=admin-user").text
            detail = reader.get(f"/console/fragments/audit/{request_id.group(1)}")
            csv = reader.get("/console/audit.csv?principal=admin-user").text
    assert "admin-user" not in forced
    assert detail.status_code == 404
    assert "admin-user" not in csv
    assert "reader-user" in csv


# -- admin actions work ----------------------------------------------------------------------


async def test_a_key_is_created_shown_once_works_and_can_be_revoked(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as admin:
        created = admin.post(
            "/console/keys/create",
            data={
                "csrf_token": csrf(admin, "/console/keys"),
                "user_id": "alice",
                "roles": ["reader"],
                "label": "laptop",
            },
        )
        assert created.status_code == 200
        secret = re.search(r"(wdn_[A-Za-z0-9_-]{20,})", created.text)
        assert secret, "the new key is shown once"
        assert secret.group(1) not in admin.get("/console/keys").text, "and only once"

        login = httpx.post(
            gateway.url + "/console/login", data={"api_key": secret.group(1)}, timeout=20
        )
        assert login.status_code == 303

        # A key's lookup prefix is the 8 characters after `wdn_`.
        prefix_value = secret.group(1)[4:12]
        revoked = admin.post(
            "/console/keys/revoke",
            data={"csrf_token": csrf(admin, "/console/keys"), "prefix": prefix_value},
        )
        assert revoked.status_code == 200
        after = httpx.post(
            gateway.url + "/console/login", data={"api_key": secret.group(1)}, timeout=20
        )
    assert after.status_code == 401


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"user_id": "", "roles": ["reader"]}, "User id"),
        ({"user_id": "bad name!", "roles": ["reader"]}, "User id"),
        ({"user_id": "bob"}, "at least one role"),
        ({"user_id": "bob", "roles": ["superuser"]}, "Unknown role"),
    ],
)
async def test_bad_key_requests_are_explained_and_create_nothing(
    data: dict[str, Any], message: str, tmp_path: Path
) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as admin:
        response = admin.post(
            "/console/keys/create", data={"csrf_token": csrf(admin, "/console/keys"), **data}
        )
    assert response.status_code == 400
    assert message in response.text
    assert "wdn_" not in response.text.split("<table", 1)[0]


async def test_quarantine_then_approve_a_tool(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as admin:
        token = csrf(admin, "/console/tools")
        quarantined = admin.post(
            "/console/tools/notes_db__search_notes/quarantine",
            data={"csrf_token": token, "reason": "checking"},
        )
        assert "quarantined" in quarantined.text
        refused = run_call(admin, "editor", "notes_db__search_notes", '{"query": "x"}')
        assert "WARDEN_DENIED:quarantined" in refused
        approved = admin.post(
            "/console/tools/notes_db__search_notes/approve", data={"csrf_token": token}
        )
        assert "approved and pinned" in approved.text
        allowed = run_call(admin, "editor", "notes_db__search_notes", '{"query": "x"}')
    assert "Allowed" in allowed


async def test_policy_reload_reports_its_result(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as admin:
        response = admin.post(
            "/console/policy/reload", data={"csrf_token": csrf(admin, "/console/policy")}
        )
    assert response.status_code == 200
    assert "Reload:" in response.text


async def test_the_policy_page_shows_constraints_and_what_each_role_sees(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as admin:
        page = admin.get("/console/policy").text
    # Jinja escapes the quotes around the prefix as &#34;.
    assert "starts with &#34;.&#34;" in page
    assert "editor-files-read" in page
    assert "Sees" in page


# -- hostile values and headers -------------------------------------------------------------


async def test_a_hostile_tool_name_is_escaped_everywhere_it_is_shown(tmp_path: Path) -> None:
    hostile = '<img src=x onerror="alert(1)">'
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "admin") as admin:
        result = run_call(admin, "admin", hostile, "{}")
        audit = admin.get("/console/audit").text
        overview = admin.get("/console").text
    for page in (result, audit, overview):
        assert "<img src=x" not in page
    assert "&lt;img src=x" in audit


async def test_console_pages_carry_the_security_headers(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "reader") as client:
        response = client.get("/console")
        css = client.get("/console/static/console.css")
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert css.headers["content-type"].startswith("text/css")


async def test_sign_out_ends_the_session(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway, signed_in(gateway, "reader") as client:
        token = csrf(client)
        assert client.post("/console/logout", data={"csrf_token": token}).status_code == 303
        assert "Sign in to the console" in client.get("/console").text
