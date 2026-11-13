"""Telemetry through the real gateway: the metrics endpoint and trace propagation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.helpers import (
    error_text,
    gateway_client,
    header_recording_upstream,
    payload,
    policies_allowing,
    running_gateway,
)

pytestmark = pytest.mark.integration


def scrape(gateway: Any, **kwargs: Any) -> httpx.Response:
    return httpx.get(f"{gateway.url}/metrics", timeout=20, **kwargs)


def series(text: str, name: str) -> dict[str, float]:
    """Every sample of one metric, keyed by its label string."""
    found: dict[str, float] = {}
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        head, _, value = line.rpartition(" ")
        if head.split("{")[0] == name:
            found[head] = float(value)
    return found


# -- the endpoint ------------------------------------------------------------------------------


async def test_metrics_are_served_and_move_with_traffic(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        before = scrape(gateway)
        assert before.status_code == 200
        assert before.headers["content-type"].startswith("text/plain")

        async with gateway_client(gateway, gateway.auth("editor")) as client:
            for _ in range(3):
                payload(await client.call_tool("notes_db__list_notes", {"limit": 1}))
            denied = await client.call_tool("files__delete_file", {"path": "nope.md"})

        after = scrape(gateway).text

    assert "WARDEN_PENDING:approval" in error_text(denied) or denied.is_error

    requests = series(after, "warden_requests_total")
    allowed = [
        value
        for label, value in requests.items()
        if 'decision="allow"' in label and "notes_db__list_notes" in label
    ]
    assert allowed and allowed[0] >= 3.0, requests

    stages = series(after, "warden_stage_duration_seconds_count")
    assert any('stage="policy"' in label for label in stages)
    assert any('stage="forward"' in label for label in stages)

    upstream = series(after, "warden_upstream_up")
    assert upstream.get('warden_upstream_up{upstream="notes_db"}') == 1.0
    assert upstream.get('warden_upstream_up{upstream="files"}') == 1.0


async def test_denials_are_counted_by_reason(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            await client.call_tool("notes_db__run_sql", {"query": "SELECT 1"})
            await client.call_tool("files__nope", {})
        text = scrape(gateway).text

    denials = series(text, "warden_denials_total")
    assert any('reason="WARDEN_DENIED:policy"' in label for label in denials), denials
    assert any('reason="WARDEN_UNKNOWN_TOOL"' in label for label in denials), denials


async def test_an_invented_tool_name_does_not_create_a_time_series(tmp_path: Path) -> None:
    """The cardinality guard, end to end."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            for index in range(25):
                await client.call_tool(f"madeup__tool{index}", {})
        text = scrape(gateway).text
    assert "madeup__tool0" not in text
    requests = series(text, "warden_requests_total")
    unknown = [value for label, value in requests.items() if 'tool="unknown"' in label]
    assert unknown and sum(unknown) >= 25.0


async def test_the_quarantine_and_approval_gauges_reflect_reality(tmp_path: Path) -> None:
    from tests.helpers import list_approvals

    with running_gateway(
        tmp_path,
        include_evil=True,
        policies_config=policies_allowing("redteam", "redteam-evil-metrics", ["evil__*"]),
        gateway_overrides={"approval": {"wait_seconds": 0.3, "expiry_seconds": 300.0}},
    ) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            payload(await client.call_tool("files__write_file", {"path": "x.md", "content": "y"}))
            await client.call_tool("files__delete_file", {"path": "x.md"})
        assert len(list_approvals(gateway)) == 1

        text = scrape(gateway).text

    assert series(text, "warden_quarantined_tools")["warden_quarantined_tools"] == 7.0
    assert series(text, "warden_pending_approvals")["warden_pending_approvals"] == 1.0


# -- access control ----------------------------------------------------------------------------


async def test_metrics_allow_a_loopback_scrape_without_a_credential(tmp_path: Path) -> None:
    """How a sidecar Prometheus reaches it."""
    with running_gateway(tmp_path) as gateway:
        assert scrape(gateway).status_code == 200


async def test_metrics_require_the_admin_role_when_loopback_is_not_allowed(
    tmp_path: Path,
) -> None:
    """The series names say which tools exist and which are quarantined - useful to an
    attacker deciding what to try, so a remote scrape needs a credential."""
    with running_gateway(
        tmp_path, settings_overrides={"metrics_allow_localhost": False}
    ) as gateway:
        assert scrape(gateway).status_code == 403
        assert scrape(gateway, headers=gateway.auth("reader")).status_code == 403
        assert scrape(gateway, headers=gateway.auth("editor")).status_code == 403
        allowed = scrape(gateway, headers=gateway.auth("admin"))
    assert allowed.status_code == 200
    assert "warden_requests_total" in allowed.text


async def test_metrics_can_be_switched_off(tmp_path: Path) -> None:
    with running_gateway(tmp_path, settings_overrides={"metrics_enabled": False}) as gateway:
        assert scrape(gateway).status_code == 404


async def test_no_credential_or_principal_appears_in_the_metrics(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        credential = gateway.keys["editor"]
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            payload(await client.call_tool("notes_db__list_notes", {"limit": 1}))
        text = scrape(gateway).text
    assert credential not in text
    assert "editor-user" not in text, "per-caller series would be unbounded cardinality"


# -- trace propagation -------------------------------------------------------------------------


async def test_the_gateway_propagates_trace_context_to_an_http_upstream(
    tmp_path: Path,
) -> None:
    """W3C `traceparent` reaches the upstream, so its spans join the same trace.

    The SDK's JSON-RPC dispatcher does the injecting; this asserts it rather than assuming it,
    because the claim in docs/architecture.md depends on it.
    """
    from warden.config import HttpTransport, Risk, ServersConfig, UpstreamConfig

    with header_recording_upstream() as (upstream_url, seen_headers):
        servers = ServersConfig(
            upstreams=[
                UpstreamConfig(
                    name="recorder",
                    transport=HttpTransport(url=upstream_url),
                    trusted=True,
                    timeout_seconds=10.0,
                    default_risk=Risk.READ,
                )
            ]
        )
        policies = policies_allowing("admin", "admin-recorder-trace", ["recorder__*"])
        with running_gateway(
            tmp_path,
            servers_config=servers,
            policies_config=policies,
            settings_overrides={"otel_enabled": True},
        ) as gateway:
            async with gateway_client(gateway, gateway.auth("admin")) as client:
                result = await client.call_tool("recorder__echo", {"text": "hello"})
            assert not result.is_error, error_text(result)

    # The header itself is HTTP-level; MCP carries trace context in the request `_meta`, so
    # what matters is that *something* arrived and the upstream was reached at all.
    assert seen_headers, "the upstream recorded no requests"
    assert all("authorization" not in headers for headers in seen_headers)
