"""HTTP authentication: what a caller gets when the credential is missing or wrong."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from warden.auth.api_keys import ApiKeyStore
from warden.auth.middleware import (
    AuthenticationFailed,
    Authenticator,
    AuthMiddleware,
    extract_bearer,
    principal_from_request,
)
from warden.auth.tokens import TokenService

pytestmark = pytest.mark.unit

RESOURCE_METADATA = "http://localhost:8080/.well-known/oauth-protected-resource"


def build_app(authenticator: Authenticator) -> Starlette:
    async def whoami(request: Request) -> JSONResponse:
        principal = principal_from_request(request)
        return JSONResponse(
            {
                "user": principal.user_id if principal else None,
                "roles": list(principal.roles) if principal else [],
                "method": principal.auth_method if principal else None,
            }
        )

    app = Starlette(
        routes=[
            Route("/mcp", whoami, methods=["GET", "POST"]),
            Route("/healthz", whoami, methods=["GET"]),
            Route("/admin/audit", whoami, methods=["GET"]),
        ]
    )
    app.add_middleware(
        AuthMiddleware,
        authenticator=authenticator,
        protected_prefixes=("/mcp", "/admin"),
        resource_metadata_url=RESOURCE_METADATA,
    )
    return app


@pytest.fixture
def client(api_keys: ApiKeyStore, tokens: TokenService) -> TestClient:
    return TestClient(build_app(Authenticator(api_keys=api_keys, tokens=tokens)))


def test_health_is_public(client: TestClient) -> None:
    """A load balancer has no credential, so liveness must not require one."""
    assert client.get("/healthz").status_code == 200


def test_missing_header_is_401_with_www_authenticate(client: TestClient) -> None:
    response = client.get("/mcp")
    assert response.status_code == 401
    challenge = response.headers["WWW-Authenticate"]
    assert challenge.startswith("Bearer ")
    assert f'resource_metadata="{RESOURCE_METADATA}"' in challenge
    assert "Traceback" not in response.text


@pytest.mark.parametrize(
    "header",
    [
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "Bearer ",
        "bearer    ",
        "Token wdn_abc",
        "",
        "Digest username=x",
    ],
)
def test_malformed_or_wrong_scheme_is_401(client: TestClient, header: str) -> None:
    response = client.get("/mcp", headers={"Authorization": header})
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_unknown_credential_is_401(client: TestClient) -> None:
    response = client.get(
        "/mcp", headers={"Authorization": "Bearer wdn_notarealkeyatall000000000000000"}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


def test_garbage_credential_is_401(client: TestClient) -> None:
    response = client.get("/mcp", headers={"Authorization": "Bearer not-a-credential"})
    assert response.status_code == 401
    assert "not a recognised format" in response.json()["error_description"]


def test_an_over_long_credential_is_refused_without_a_lookup(client: TestClient) -> None:
    response = client.get("/mcp", headers={"Authorization": f"Bearer {'x' * 20000}"})
    assert response.status_code == 401


async def test_a_valid_api_key_authenticates(api_keys: ApiKeyStore, tokens: TokenService) -> None:
    generated = await api_keys.create("alice", ["reader"])
    with TestClient(build_app(Authenticator(api_keys=api_keys, tokens=tokens))) as client:
        response = client.get("/mcp", headers={"Authorization": f"Bearer {generated.secret}"})
    assert response.status_code == 200
    assert response.json() == {"user": "alice", "roles": ["reader"], "method": "api_key"}


async def test_a_valid_token_authenticates(api_keys: ApiKeyStore, tokens: TokenService) -> None:
    issued = tokens.issue("bob", ["editor"])
    with TestClient(build_app(Authenticator(api_keys=api_keys, tokens=tokens))) as client:
        response = client.get("/mcp", headers={"Authorization": f"Bearer {issued.token}"})
    assert response.status_code == 200
    assert response.json() == {"user": "bob", "roles": ["editor"], "method": "jwt"}


async def test_a_revoked_api_key_is_401(api_keys: ApiKeyStore, tokens: TokenService) -> None:
    generated = await api_keys.create("alice", ["reader"])
    await api_keys.revoke(generated.prefix)
    with TestClient(build_app(Authenticator(api_keys=api_keys, tokens=tokens))) as client:
        response = client.get("/mcp", headers={"Authorization": f"Bearer {generated.secret}"})
    assert response.status_code == 401
    assert "revoked" in response.json()["error_description"]


def test_admin_paths_are_protected_too(client: TestClient) -> None:
    assert client.get("/admin/audit").status_code == 401


async def test_a_backend_failure_fails_closed(tokens: TokenService) -> None:
    """If the credential store is unreachable we must refuse, not let the caller through."""

    class BrokenKeyStore:
        async def verify(self, credential: str) -> Any:
            raise ConnectionError("postgres is down")

    authenticator = Authenticator(api_keys=BrokenKeyStore(), tokens=tokens)  # type: ignore[arg-type]
    with TestClient(build_app(authenticator)) as client:
        response = client.get(
            "/mcp", headers={"Authorization": "Bearer wdn_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        )
    assert response.status_code == 401
    assert "unavailable" in response.json()["error_description"]


async def test_the_401_body_never_echoes_the_credential(
    api_keys: ApiKeyStore, tokens: TokenService
) -> None:
    secret = "wdn_canarycanarycanarycanary00000"
    with TestClient(build_app(Authenticator(api_keys=api_keys, tokens=tokens))) as client:
        response = client.get("/mcp", headers={"Authorization": f"Bearer {secret}"})
    assert secret not in response.text
    assert secret not in str(dict(response.headers))


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([(b"authorization", b"Bearer abc")], "abc"),
        ([(b"Authorization", b"bearer   abc  ")], "abc"),
        ([(b"authorization", b"Basic abc")], None),
        ([(b"authorization", b"Bearer")], None),
        ([(b"accept", b"*/*")], None),
        ([], None),
    ],
)
def test_extract_bearer(headers: list[tuple[bytes, bytes]], expected: str | None) -> None:
    assert extract_bearer(headers) == expected


async def test_authenticator_without_backends_refuses_everything() -> None:
    authenticator = Authenticator()
    with pytest.raises(AuthenticationFailed, match="not enabled"):
        await authenticator.authenticate("wdn_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    with pytest.raises(AuthenticationFailed, match="not enabled"):
        await authenticator.authenticate("a.b.c")


def test_principal_from_request_handles_no_request() -> None:
    assert principal_from_request(None) is None


# -- optional authentication -------------------------------------------------------------------


def build_app_with_optional(authenticator: Authenticator) -> Starlette:
    """An app where /metrics verifies a credential if one is sent but does not require one."""

    async def whoami(request: Request) -> JSONResponse:
        principal = principal_from_request(request)
        return JSONResponse({"user": principal.user_id if principal else None})

    app = Starlette(routes=[Route("/metrics", whoami, methods=["GET"])])
    app.add_middleware(
        AuthMiddleware,
        authenticator=authenticator,
        protected_prefixes=("/mcp",),
        optional_prefixes=("/metrics",),
        resource_metadata_url=RESOURCE_METADATA,
    )
    return app


async def test_an_optional_path_works_without_a_credential(
    api_keys: ApiKeyStore, tokens: TokenService
) -> None:
    app = build_app_with_optional(Authenticator(api_keys=api_keys, tokens=tokens))
    with TestClient(app) as client:
        response = client.get("/metrics")
    assert response.status_code == 200
    assert response.json() == {"user": None}


async def test_an_optional_path_attaches_a_valid_credential(
    api_keys: ApiKeyStore, tokens: TokenService
) -> None:
    generated = await api_keys.create("admin-user", ["admin"])
    app = build_app_with_optional(Authenticator(api_keys=api_keys, tokens=tokens))
    with TestClient(app) as client:
        response = client.get("/metrics", headers={"Authorization": f"Bearer {generated.secret}"})
    assert response.json() == {"user": "admin-user"}


async def test_an_optional_path_still_rejects_a_wrong_credential(
    api_keys: ApiKeyStore, tokens: TokenService
) -> None:
    """Silently ignoring a bad credential would hide a misconfigured scraper."""
    app = build_app_with_optional(Authenticator(api_keys=api_keys, tokens=tokens))
    with TestClient(app) as client:
        response = client.get("/metrics", headers={"Authorization": "Bearer wdn_" + "x" * 32})
    assert response.status_code == 401
