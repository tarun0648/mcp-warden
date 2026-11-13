"""Readiness against the real Postgres and Redis from docker compose."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests.conftest import requires_postgres, requires_redis
from warden.config import Settings
from warden.health import Readiness, postgres_check, redis_check
from warden.main import create_app

pytestmark = pytest.mark.integration


@requires_postgres
@requires_redis
def test_readyz_200_against_real_services() -> None:
    settings = Settings(
        database_url="postgresql+asyncpg://warden:warden_dev_password_change_me@localhost:5432/warden",
        redis_url="redis://localhost:6379/15",
        log_level="WARNING",
    )
    readiness = Readiness(
        {
            "postgres": postgres_check(settings.database_url),
            "redis": redis_check(settings.redis_url),
        }
    )
    with TestClient(create_app(settings, readiness=readiness)) as client:
        response = client.get("/readyz")
    assert response.status_code == 200, response.text


def test_readyz_503_when_a_service_is_not_listening() -> None:
    """A port nothing listens on must produce a 503 that names that dependency."""
    settings = Settings(
        database_url="postgresql+asyncpg://warden:warden@127.0.0.1:1/warden",
        redis_url="redis://127.0.0.1:1/0",
        log_level="WARNING",
    )
    readiness = Readiness(
        {
            "postgres": postgres_check(settings.database_url),
            "redis": redis_check(settings.redis_url),
        },
        timeout=2.0,
    )
    with TestClient(create_app(settings, readiness=readiness)) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert set(response.json()["unavailable"]) == {"postgres", "redis"}
