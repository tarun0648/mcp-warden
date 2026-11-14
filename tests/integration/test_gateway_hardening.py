"""Hardening checks against a real gateway on a real port."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from tests.helpers import running_gateway

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


async def test_an_oversized_mcp_body_is_refused_with_413(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        limit = gateway.app.state.gateway_config.limits.max_request_body_bytes
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "notes_db__create_note", "arguments": {"body": "x" * limit}},
            }
        )
        response = httpx.post(
            gateway.mcp_url,
            content=body,
            headers={**MCP_HEADERS, **gateway.auth("editor")},
            timeout=20,
        )
    assert response.status_code == 413
    assert response.json()["error"] == "payload_too_large"
    assert response.headers.get("x-request-id"), "a refusal still carries a request id"


async def test_an_oversized_body_is_refused_even_without_credentials(tmp_path: Path) -> None:
    """Refusing it costs nothing; reading it to find out who sent it would."""
    with running_gateway(tmp_path) as gateway:
        limit = gateway.app.state.gateway_config.limits.max_request_body_bytes
        response = httpx.post(
            gateway.mcp_url, content=b"x" * (limit + 1), headers=MCP_HEADERS, timeout=20
        )
    assert response.status_code == 413


async def test_a_json_rpc_batch_is_refused(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        response = httpx.post(
            gateway.mcp_url,
            json=batch,
            headers={**MCP_HEADERS, **gateway.auth("editor")},
            timeout=20,
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32600


async def test_an_ordinary_session_still_works_under_the_limits(tmp_path: Path) -> None:
    """The limits must not cost a legitimate client anything."""
    from tests.helpers import gateway_client

    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            listing = await client.list_tools()
            result = await client.call_tool("notes_db__list_notes", {})
    assert listing.tools
    assert not result.is_error


async def test_the_approval_page_sends_its_security_headers(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        page = httpx.get(f"{gateway.url}/approvals", timeout=20)
        css = httpx.get(f"{gateway.url}/approvals/static/approvals.css", timeout=20)
        mcp = httpx.get(gateway.mcp_url, timeout=20)
    assert page.status_code == 200
    csp = page.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["referrer-policy"] == "no-referrer"
    assert page.headers["cache-control"] == "no-store"
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert "content-security-policy" not in mcp.headers


async def test_a_failed_login_also_carries_the_headers(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        refused = httpx.post(
            f"{gateway.url}/approvals/login", data={"api_key": "wdn_wrong"}, timeout=20
        )
    assert refused.status_code == 401
    assert "content-security-policy" in refused.headers


async def test_the_page_references_only_what_the_policy_allows(tmp_path: Path) -> None:
    """A CSP that blocks the page's own stylesheet would be a broken page, not a safe one."""
    with running_gateway(tmp_path) as gateway:
        page = httpx.get(f"{gateway.url}/approvals", timeout=20)
    assert 'href="/approvals/static/approvals.css"' in page.text
    assert "<style" not in page.text


# -- DNS rebinding -----------------------------------------------------------------------------


async def test_a_request_for_a_foreign_host_name_is_refused(tmp_path: Path) -> None:
    """DNS rebinding: a web page re-points its own domain at 127.0.0.1 and drives a local
    gateway from the user's browser. The browser then sends that domain in `Host`, which is
    the one thing the page cannot forge, so the gateway refuses any host it was not told about.
    """
    with running_gateway(tmp_path) as gateway:
        response = httpx.post(
            gateway.mcp_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={**MCP_HEADERS, **gateway.auth("editor"), "Host": "attacker.example"},
            timeout=20,
        )
    # 421 Misdirected Request, specifically: an unprotected gateway would answer 400 here
    # (no session yet), so accepting 400 would let this test pass with the protection off.
    assert response.status_code == 421, response.status_code
    assert "Host" in response.text


async def test_a_cross_origin_browser_request_is_refused(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        response = httpx.post(
            gateway.mcp_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={**MCP_HEADERS, **gateway.auth("editor"), "Origin": "https://attacker.example"},
            timeout=20,
        )
    assert response.status_code == 403, response.status_code
    assert "Origin" in response.text


async def test_the_gateways_own_host_name_is_accepted(tmp_path: Path) -> None:
    """The control: the same request with a legitimate Host is not refused for its host."""
    with running_gateway(tmp_path) as gateway:
        port = gateway.url.rsplit(":", 1)[1]
        response = httpx.post(
            gateway.mcp_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={**MCP_HEADERS, **gateway.auth("editor"), "Host": f"localhost:{port}"},
            timeout=20,
        )
    # Not 403/421: authentication and host checks passed. The MCP layer may still answer 400
    # for a request outside an initialised session, which is the expected next refusal.
    assert response.status_code == 400, response.status_code
    assert "session" in response.text.lower(), "refused by the MCP layer, not by the host check"
