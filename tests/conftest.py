"""Shared fixtures. Nothing here may touch the network or Docker."""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from warden.config import (
    GatewayConfig,
    PoliciesConfig,
    ServersConfig,
    Settings,
    load_gateway_config,
    load_policies_config,
    load_servers_config,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"

#: A fake secret used by the "no secret ever leaks" tests. Never a real credential.
CANARY_SECRET = "wdn_canary_do_not_log_0123456789abcdef"


def _port_open(host: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def postgres_available() -> bool:
    return _port_open("127.0.0.1", 5432)


def redis_available() -> bool:
    return _port_open("127.0.0.1", 6379)


requires_postgres = pytest.mark.skipif(
    not postgres_available(), reason="postgres is not listening on 127.0.0.1:5432 (run `make up`)"
)
requires_redis = pytest.mark.skipif(
    not redis_available(), reason="redis is not listening on 127.0.0.1:6379 (run `make up`)"
)


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings pointed at a temp directory, so no test touches real data."""
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'warden.sqlite3'}",
        redis_url="redis://localhost:6379/15",
        config_dir=CONFIG_DIR,
        jwt_key_dir=tmp_path / "keys",
        log_level="WARNING",
        otel_enabled=False,
        classifier_enabled=False,
    )


@pytest.fixture
def gateway_config() -> GatewayConfig:
    return load_gateway_config(CONFIG_DIR / "gateway.yaml")


@pytest.fixture
def servers_config() -> ServersConfig:
    return load_servers_config(CONFIG_DIR / "servers.yaml")


@pytest.fixture
def policies_config() -> PoliciesConfig:
    return load_policies_config(CONFIG_DIR / "policies.yaml")


@pytest.fixture
def clean_env() -> Iterator[None]:
    """Run a test with WARDEN_* and dependency env vars removed."""
    saved = dict(os.environ)
    for key in list(os.environ):
        if key.startswith(("WARDEN_", "JWT_", "OTEL_", "CLASSIFIER_")) or key in {
            "DATABASE_URL",
            "REDIS_URL",
        }:
            del os.environ[key]
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)
