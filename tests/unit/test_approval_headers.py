"""Security headers on the approval UI, and the template changes that make the CSP possible."""

from __future__ import annotations

import re
from typing import Any

import pytest

from warden.approval.web import (
    CONTENT_SECURITY_POLICY,
    HTMX_URL,
    SECURITY_HEADERS,
    TEMPLATE_DIR,
    ApprovalSecurityHeaders,
)

pytestmark = [pytest.mark.unit, pytest.mark.anyio]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def headers_for(
    path: str, existing: list[tuple[bytes, bytes]] | None = None
) -> dict[str, str]:
    async def app(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": existing or []})
        await send({"type": "http.response.body", "body": b""})

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b""}

    await ApprovalSecurityHeaders(app)({"type": "http", "path": path, "headers": []}, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    return {bytes(k).decode(): bytes(v).decode() for k, v in start["headers"]}


@pytest.mark.parametrize(
    "path", ["/approvals", "/approvals/queue", "/approvals/login", "/approvals/static/x.css"]
)
async def test_every_approval_response_carries_the_headers(path: str) -> None:
    headers = await headers_for(path)
    for name, value in SECURITY_HEADERS:
        assert headers.get(name) == value, name


@pytest.mark.parametrize("path", ["/mcp", "/admin/approvals", "/approvalsx", "/healthz"])
async def test_other_paths_are_left_alone(path: str) -> None:
    """The MCP endpoint and the JSON admin API are not documents; a CSP there means nothing."""
    headers = await headers_for(path)
    assert "content-security-policy" not in headers


async def test_a_header_the_handler_set_is_not_duplicated_or_overridden() -> None:
    headers = await headers_for("/approvals", existing=[(b"cache-control", b"private")])
    assert headers["cache-control"] == "private"


def test_the_policy_forbids_inline_script_and_style() -> None:
    assert "'unsafe-inline'" not in CONTENT_SECURITY_POLICY
    assert "'unsafe-eval'" not in CONTENT_SECURITY_POLICY
    assert "default-src 'none'" in CONTENT_SECURITY_POLICY
    assert "frame-ancestors 'none'" in CONTENT_SECURITY_POLICY
    assert "form-action 'self'" in CONTENT_SECURITY_POLICY


def test_the_only_script_source_is_the_pinned_htmx_file() -> None:
    script_src = next(
        part for part in CONTENT_SECURITY_POLICY.split("; ") if part.startswith("script-src")
    )
    assert script_src == f"script-src {HTMX_URL}"
    assert "@" in HTMX_URL and HTMX_URL.endswith(".js"), "pinned to an exact version and file"


def test_framing_is_refused_by_both_mechanisms() -> None:
    assert dict(SECURITY_HEADERS)["x-frame-options"] == "DENY"


# -- the templates must be CSP-clean, or the CSP breaks the page ---------------------------------


def templates() -> dict[str, str]:
    """Each template as it can reach the browser: Jinja comments are never rendered."""
    return {
        p.name: re.sub(r"\{#.*?#\}", "", p.read_text(), flags=re.S)
        for p in TEMPLATE_DIR.glob("*.html")
    }


def test_no_template_has_an_inline_style_attribute_or_block() -> None:
    for name, text in templates().items():
        assert "style=" not in text, name
        assert "<style" not in text, name


def test_no_template_has_inline_script() -> None:
    for name, text in templates().items():
        for match in re.finditer(r"<script\b([^>]*)>", text):
            assert "src=" in match.group(1), f"{name}: inline <script>"
        assert not re.search(r"\son[a-z]+\s*=", text), f"{name}: inline event handler"


def test_the_script_tag_matches_the_policy_and_carries_an_integrity_hash() -> None:
    base = templates()["base.html"]
    tag = re.search(r"<script\b[^>]*>", base, flags=re.S)
    assert tag is not None
    assert f'src="{HTMX_URL}"' in tag.group(0)
    assert 'integrity="sha384-' in tag.group(0)


def test_htmx_is_told_not_to_evaluate_or_inject_styles() -> None:
    base = templates()["base.html"]
    assert '"allowEval": false' in base
    assert '"allowScriptTags": false' in base
    assert '"includeIndicatorStyles": false' in base
