"""Health and readiness endpoints, with fake dependency checks."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from warden.config import Settings
from warden.health import Readiness
from warden.main import create_app

pytestmark = pytest.mark.unit


def _app(settings: Settings, checks: dict[str, object]) -> TestClient:
    readiness = Readiness(checks)  # type: ignore[arg-type]
    return TestClient(create_app(settings, readiness=readiness, mount_mcp=False))


async def _ok() -> None:
    return None


async def _down() -> str:
    return "connection refused"


async def _boom() -> None:
    raise RuntimeError("socket closed")


def test_healthz_is_always_ok(settings: Settings) -> None:
    with _app(settings, {"postgres": _down}) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_ok_when_all_dependencies_answer(settings: Settings) -> None:
    with _app(settings, {"postgres": _ok, "redis": _ok}) as client:
        response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"postgres": "ok", "redis": "ok"}}


def test_readyz_503_names_the_dependency_that_is_down(settings: Settings) -> None:
    with _app(settings, {"postgres": _ok, "redis": _down}) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["unavailable"] == ["redis"]
    assert body["checks"]["redis"] == "connection refused"
    assert body["checks"]["postgres"] == "ok"


def test_readyz_treats_an_exception_as_not_ready(settings: Settings) -> None:
    with _app(settings, {"postgres": _boom, "redis": _ok}) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert "RuntimeError" in response.json()["checks"]["postgres"]


def test_readyz_times_out_a_hanging_dependency(settings: Settings) -> None:
    import asyncio

    async def hangs() -> None:
        await asyncio.sleep(5)

    readiness = Readiness({"postgres": hangs}, timeout=0.05)
    with TestClient(create_app(settings, readiness=readiness, mount_mcp=False)) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert "timed out" in response.json()["checks"]["postgres"]


def test_request_id_header_is_echoed(settings: Settings) -> None:
    with _app(settings, {"postgres": _ok}) as client:
        response = client.get("/healthz", headers={"x-request-id": "abc-123"})
    assert response.headers["x-request-id"] == "abc-123"


def test_hostile_request_id_is_replaced(settings: Settings) -> None:
    with _app(settings, {"postgres": _ok}) as client:
        response = client.get("/healthz", headers={"x-request-id": 'bad"\n{"level":"FAKE"'})
    echoed = response.headers["x-request-id"]
    assert '"' not in echoed and "\n" not in echoed
    assert len(echoed) == 32
