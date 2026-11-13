"""Authentication through the real gateway: credentials, 401s, JWKS, no token passthrough."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import httpx
import pytest

from tests.helpers import (
    REPO_ROOT,
    gateway_client,
    header_recording_upstream,
    http_get,
    payload,
    running_gateway,
    stdio_upstream,
)

pytestmark = pytest.mark.integration

CANARY_KEY_MARKER = "wdn_"


async def test_a_valid_api_key_can_list_and_call_tools(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            listing = await client.list_tools()
            assert listing.tools
            result = await client.call_tool("notes_db__list_notes", {"limit": 1})
    assert len(payload(result)["notes"]) == 1


async def test_no_credential_is_refused_at_the_transport(tmp_path: Path) -> None:
    """The MCP handshake itself must fail, so an unauthenticated client never gets a session."""
    with running_gateway(tmp_path) as gateway:
        response = httpx.post(
            gateway.mcp_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Accept": "application/json, text/event-stream"},
            timeout=10,
        )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert "resource_metadata" in response.headers["WWW-Authenticate"]


@pytest.mark.parametrize(
    "header",
    ["Bearer wdn_wrongwrongwrongwrongwrongwrong0", "Basic YWxpY2U6cA==", "Bearer nonsense"],
)
async def test_bad_credentials_are_refused(tmp_path: Path, header: str) -> None:
    with running_gateway(tmp_path) as gateway:
        response = httpx.post(
            gateway.mcp_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Accept": "application/json, text/event-stream", "Authorization": header},
            timeout=10,
        )
    assert response.status_code == 401


async def test_a_revoked_key_stops_working_without_a_restart(tmp_path: Path) -> None:
    from tests.helpers import run_async
    from warden.auth.api_keys import ApiKeyStore
    from warden.db.engine import Database

    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            assert (await client.list_tools()).tools is not None

        prefix = gateway.keys["reader"][len(CANARY_KEY_MARKER) :][:8]

        async def revoke() -> int:
            database = Database(gateway.database_url)
            try:
                return await ApiKeyStore(database).revoke(prefix)
            finally:
                await database.dispose()

        assert run_async(revoke) == 1

        response = httpx.post(
            gateway.mcp_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {gateway.keys['reader']}",
            },
            timeout=10,
        )
    assert response.status_code == 401
    assert "revoked" in response.json()["error_description"]


async def test_a_jwt_issued_by_the_gateway_works(tmp_path: Path) -> None:
    from warden.auth.jwt_keys import JwtKeyStore
    from warden.auth.tokens import TokenConfig, TokenService
    from warden.config import Settings

    with running_gateway(tmp_path) as gateway:
        settings: Settings = gateway.app.state.settings
        service = TokenService(
            JwtKeyStore(settings.jwt_key_dir),
            TokenConfig(issuer=settings.jwt_issuer, audience=settings.jwt_audience),
        )
        issued = service.issue("carol", ["admin"], ttl_seconds=300)
        async with gateway_client(gateway, {"Authorization": f"Bearer {issued.token}"}) as client:
            result = await client.call_tool("notes_db__list_notes", {"limit": 2})
    assert len(payload(result)["notes"]) == 2


async def test_jwks_is_public_and_carries_no_private_material(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        response = http_get(f"{gateway.url}/.well-known/jwks.json")
    assert response.status_code == 200
    document = response.json()
    assert document["keys"], "the gateway must publish its active signing key"
    serialised = json.dumps(document)
    assert "PRIVATE" not in serialised and '"d"' not in serialised
    for key in document["keys"]:
        assert key["alg"] == "ES256" and key["kty"] == "EC"


async def test_protected_resource_metadata_is_public(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        response = http_get(f"{gateway.url}/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    body = response.json()
    assert body["resource"].endswith("/mcp")
    assert body["authorization_servers"]
    assert body["bearer_methods_supported"] == ["header"]


async def test_health_endpoints_stay_public(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        assert http_get(f"{gateway.url}/healthz").status_code == 200
        assert http_get(f"{gateway.url}/readyz").status_code == 200


async def test_the_client_credential_is_never_forwarded_to_an_upstream(tmp_path: Path) -> None:
    """No token passthrough. An upstream must never see the caller's Authorization header."""
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
        with running_gateway(tmp_path, servers_config=servers) as gateway:
            client_credential = gateway.keys["admin"]
            async with gateway_client(gateway, gateway.auth("admin")) as client:
                result = await client.call_tool("recorder__echo", {"text": "hello"})
            assert not result.is_error

    assert seen_headers, "the upstream recorded no requests"
    for headers in seen_headers:
        assert "authorization" not in headers, (
            f"the upstream received an Authorization header: {headers.get('authorization')}"
        )
        assert client_credential not in json.dumps(headers)


async def test_the_api_key_never_reaches_the_database_or_a_log(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Hard rule 2, end to end: use a key for real calls, then grep everything for it."""
    with running_gateway(tmp_path) as gateway:
        secret = gateway.keys["admin"]
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            await client.list_tools()
            await client.call_tool("notes_db__list_notes", {"limit": 1})
            await client.call_tool("notes_db__search_notes", {"query": "password"})
        database_path = gateway.database_url.split(":///")[1]

    captured = capfd.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err

    connection = sqlite3.connect(database_path)
    try:
        dumped = "\n".join(connection.iterdump())
    finally:
        connection.close()
    assert secret not in dumped, "the raw key must not be anywhere in the database"
    assert secret[len("wdn_") :][:8] in dumped, "the prefix is stored on purpose"


async def test_stdio_upstreams_do_not_inherit_the_gateways_credentials(tmp_path: Path) -> None:
    """A child process must not be able to read the gateway's secrets from its environment."""
    import os
    import subprocess
    import sys

    upstream = stdio_upstream("probe", "servers.files", {"FILES_SANDBOX_ROOT": str(tmp_path)})
    transport = upstream.transport
    env = {**os.environ, "WARDEN_TEST_SECRET": "must-not-be-inherited"}
    result = subprocess.run(
        [sys.executable, "-c", "import os,json;print(json.dumps(dict(os.environ)))"],
        cwd=str(REPO_ROOT),
        env={**{"PATH": os.environ.get("PATH", "")}, **dict(transport.env)},
        capture_output=True,
        text=True,
        check=True,
    )
    child_env = json.loads(result.stdout)
    assert "WARDEN_TEST_SECRET" not in child_env
    assert "DATABASE_URL" not in child_env
    del env
