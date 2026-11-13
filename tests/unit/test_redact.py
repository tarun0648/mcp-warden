"""redact() is hard rule 2's enforcement point, so it gets property tests as well as examples."""

from __future__ import annotations

import io
import json
import logging

import pytest
from hypothesis import given
from hypothesis import strategies as st

from warden.logging import (
    REDACTED,
    configure_logging,
    get_logger,
    is_secret_key,
    redact,
    request_id_var,
)

pytestmark = pytest.mark.unit

SECRET = "super-secret-value-9f3a"


def test_top_level_secret_keys_masked() -> None:
    out = redact({"authorization": SECRET, "tool": "files__read_file"})
    assert out == {"authorization": REDACTED, "tool": "files__read_file"}


def test_nested_secrets_masked() -> None:
    payload = {
        "request": {
            "headers": {"Authorization": f"Bearer {SECRET}", "accept": "application/json"},
            "args": {"path": "notes/a.md", "api_key": SECRET},
        }
    }
    out = redact(payload)
    assert out["request"]["headers"]["Authorization"] == REDACTED
    assert out["request"]["headers"]["accept"] == "application/json"
    assert out["request"]["args"]["path"] == "notes/a.md"
    assert out["request"]["args"]["api_key"] == REDACTED


def test_lists_are_walked() -> None:
    out = redact({"items": [{"token": SECRET}, {"name": "ok"}]})
    assert out["items"][0]["token"] == REDACTED
    assert out["items"][1]["name"] == "ok"


def test_non_secret_fields_unchanged() -> None:
    payload = {"count": 3, "ratio": 0.5, "flag": True, "none": None, "text": "hello"}
    assert redact(payload) == payload


@pytest.mark.parametrize(
    "key",
    [
        "authorization",
        "Authorization",
        "X-Authorization",
        "api_key",
        "apiKey",
        "API-KEY",
        "password",
        "db_password",
        "client_secret",
        "PRIVATE_KEY",
        "refresh_token",
        "Set-Cookie",
    ],
)
def test_secret_key_detection(key: str) -> None:
    assert is_secret_key(key)


@pytest.mark.parametrize("key", ["tokens_used", "num_tokens", "secrets"])
def test_over_matching_is_deliberate(key: str) -> None:
    """Plural forms are redacted too. Losing a metric beats leaking a credential."""
    assert is_secret_key(key)


@pytest.mark.parametrize(
    "key", ["path", "query", "note_id", "content", "title", "secretary", "tokenizer"]
)
def test_non_secret_key_detection(key: str) -> None:
    assert not is_secret_key(key), f"{key} should not be treated as a secret"


def test_cycles_do_not_hang() -> None:
    node: dict[str, object] = {"name": "root"}
    node["self"] = node
    out = redact(node)
    assert out is not None


def test_deeply_nested_is_truncated_not_leaked() -> None:
    payload: dict[str, object] = {"password": SECRET}
    for _ in range(30):
        payload = {"next": payload}
    assert SECRET not in json.dumps(redact(payload), default=str)


@given(
    # The secret is drawn from an alphabet the sibling values cannot produce, so a collision
    # cannot make this test pass or fail for the wrong reason.
    secret=st.text(alphabet="XYZ#@!", min_size=8, max_size=40),
    key=st.sampled_from(["token", "password", "api_key", "authorization", "client_secret"]),
    other=st.dictionaries(
        st.sampled_from(["path", "query", "title", "note_id"]),
        st.one_of(st.text(alphabet="abc/0123456789.", max_size=20), st.integers(), st.booleans()),
        max_size=4,
    ),
)
def test_redact_never_returns_the_secret(secret: str, key: str, other: dict[str, object]) -> None:
    payload = {**other, key: secret, "nested": {"list": [{key: secret}]}}
    rendered = json.dumps(redact(payload), default=str)
    assert secret not in rendered


def test_json_log_line_includes_request_id_and_redacts_extra() -> None:
    stream = io.StringIO()
    configure_logging("INFO", stream=stream)
    token = request_id_var.set("req-123")
    try:
        get_logger("test.redact").info(
            "handled", extra={"warden": {"tool": "files__read_file", "authorization": SECRET}}
        )
    finally:
        request_id_var.reset(token)
        logging.getLogger().handlers.clear()
    line = json.loads(stream.getvalue().strip())
    assert line["request_id"] == "req-123"
    assert line["tool"] == "files__read_file"
    assert line["authorization"] == REDACTED
    assert SECRET not in stream.getvalue()
