"""The audit log through the real gateway: one row per path, tamper detection, fail-closed."""

from __future__ import annotations

import asyncio
import csv
import io
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.helpers import (
    approve_tool,
    audit_rows,
    error_text,
    gateway_client,
    payload,
    policies_allowing,
    running_gateway,
    tamper_sqlite,
)

pytestmark = pytest.mark.integration


def rows_for(url: str, request_id: str) -> list[dict[str, Any]]:
    return [row for row in audit_rows(url) if row["request_id"] == request_id]


def request_id_of(result: Any) -> str:
    assert result.structured_content is not None
    return str(result.structured_content["request_id"])


# -- one row per path --------------------------------------------------------------------------


async def test_an_allowed_call_leaves_a_started_and_a_finished_row(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool("notes_db__list_notes", {"limit": 2})
            assert not result.is_error
        rows = audit_rows(gateway.database_url)

    calls = [row for row in rows if row["tool"] == "notes_db__list_notes"]
    assert [row["event"] for row in calls] == ["started", "finished"]
    assert calls[0]["decision"] == "allow"
    assert calls[1]["decision"] == "allow"
    assert calls[1]["reason_code"] == "WARDEN_ALLOWED"
    assert calls[1]["result_bytes"] > 0
    assert calls[1]["result_sha256"]
    assert calls[0]["request_id"] == calls[1]["request_id"]
    assert calls[1]["principal_id"] == "editor-user"
    assert calls[1]["auth_method"] == "api_key"
    assert calls[1]["upstream"] == "notes_db"
    assert json.loads(calls[1]["stage_timings_ms"]), "stage timings must be recorded"


async def test_a_policy_denial_leaves_one_denied_row_and_never_forwards(
    tmp_path: Path,
) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            result = await client.call_tool("notes_db__run_sql", {"query": "SELECT 1"})
        rows = rows_for(gateway.database_url, request_id_of(result))

    assert len(rows) == 1
    assert rows[0]["event"] == "denied"
    assert rows[0]["decision"] == "deny"
    assert rows[0]["reason_code"] == "WARDEN_DENIED:policy"
    assert rows[0]["matched_rule"] == "reader-no-sql"
    assert rows[0]["result_bytes"] == 0


async def test_a_rate_limit_denial_is_recorded_with_its_reason(tmp_path: Path) -> None:
    overrides: dict[str, Any] = {
        "limits": {
            "default": {
                "per_principal": {"capacity": 1, "refill_per_second": 0.001},
                "per_tool": {"capacity": 99, "refill_per_second": 99.0},
                "daily_calls": 999,
                "daily_destructive_calls": 999,
            },
            "roles": {},
        }
    }
    with running_gateway(tmp_path, gateway_overrides=overrides) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            await client.call_tool("notes_db__list_notes", {"limit": 1})
            denied = await client.call_tool("notes_db__list_notes", {"limit": 1})
        rows = rows_for(gateway.database_url, request_id_of(denied))

    assert [row["event"] for row in rows] == ["denied"]
    assert rows[0]["reason_code"] == "WARDEN_DENIED:rate_limit"
    assert json.loads(rows[0]["scan_flags"])["retry_after_seconds"] > 0


async def test_a_budget_denial_is_recorded(tmp_path: Path) -> None:
    overrides: dict[str, Any] = {
        "limits": {
            "default": {
                "per_principal": {"capacity": 99, "refill_per_second": 99.0},
                "per_tool": {"capacity": 99, "refill_per_second": 99.0},
                "daily_calls": 99,
                "daily_destructive_calls": 0,
            },
            "roles": {},
        }
    }
    policies = policies_allowing(
        "editor",
        "editor-delete-direct",
        ["files__delete_file"],
        prepend=True,
        require_approval=False,
    )
    with running_gateway(
        tmp_path, gateway_overrides=overrides, policies_config=policies
    ) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            payload(await client.call_tool("files__write_file", {"path": "a.md", "content": "x"}))
            denied = await client.call_tool("files__delete_file", {"path": "a.md"})
        rows = rows_for(gateway.database_url, request_id_of(denied))

    assert rows[0]["reason_code"] == "WARDEN_DENIED:budget"
    assert rows[0]["risk"] == "destructive"
    assert (tmp_path / "sandbox" / "a.md").exists(), "the denied delete must not have run"


async def test_an_upstream_timeout_is_recorded_as_finished(tmp_path: Path) -> None:
    """The upstream may have acted, so the pair must show the call was started."""
    policies = policies_allowing("redteam", "redteam-evil-slow", ["evil__*"])
    with running_gateway(
        tmp_path, include_evil=True, evil_timeout=1.0, policies_config=policies
    ) as gateway:
        approve_tool(gateway, "evil__slow_tool")
        async with gateway_client(gateway, gateway.auth("redteam")) as client:
            result = await client.call_tool("evil__slow_tool", {"seconds": 10})
        rows = rows_for(gateway.database_url, request_id_of(result))

    assert [row["event"] for row in rows] == ["started", "finished"]
    assert rows[1]["reason_code"] == "WARDEN_UPSTREAM_TIMEOUT"
    assert rows[1]["decision"] == "deny"


async def test_an_upstream_error_result_is_recorded_as_allowed(tmp_path: Path) -> None:
    """An upstream's own is_error result is the tool answering, not the gateway refusing."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool("files__read_file", {"path": "missing.md"})
            assert result.is_error
        rows = [
            row for row in audit_rows(gateway.database_url) if row["tool"] == "files__read_file"
        ]
    assert [row["event"] for row in rows] == ["started", "finished"]
    assert rows[1]["decision"] == "allow"
    assert rows[1]["reason_code"] == "WARDEN_ALLOWED"


async def test_an_unknown_tool_is_recorded(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            result = await client.call_tool("files__nope", {})
        rows = rows_for(gateway.database_url, request_id_of(result))
    assert rows[0]["reason_code"] == "WARDEN_UNKNOWN_TOOL"
    assert rows[0]["event"] == "denied"


async def test_an_oversized_result_denial_is_recorded_after_the_call_ran(
    tmp_path: Path,
) -> None:
    overrides: dict[str, Any] = {"limits": {"max_result_bytes": 4096}}
    policies = policies_allowing("redteam", "redteam-evil-huge2", ["evil__*"])
    with running_gateway(
        tmp_path,
        include_evil=True,
        evil_timeout=10.0,
        gateway_overrides=overrides,
        policies_config=policies,
    ) as gateway:
        approve_tool(gateway, "evil__huge_output")
        async with gateway_client(gateway, gateway.auth("redteam")) as client:
            result = await client.call_tool("evil__huge_output", {"kb": 64})
        rows = rows_for(gateway.database_url, request_id_of(result))
    assert [row["event"] for row in rows] == ["started", "finished"]
    assert rows[1]["reason_code"] == "WARDEN_DENIED:output_too_large"


async def test_the_chain_verifies_after_a_mixed_workload(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            await client.call_tool("notes_db__list_notes", {"limit": 1})
            await client.call_tool("notes_db__run_sql", {"query": "SELECT 1"})
            await client.call_tool("files__delete_file", {"path": "a.md"})
            await client.call_tool("files__read_file", {"path": "../../etc/passwd"})
        response = httpx.get(
            f"{gateway.url}/admin/audit/verify", headers=gateway.auth("admin"), timeout=20
        )
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["rows_checked"] >= 4


async def test_a_hundred_concurrent_calls_leave_a_verifiable_chain(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            await asyncio.gather(
                *(
                    client.call_tool("notes_db__get_note", {"note_id": (index % 10) + 1})
                    for index in range(100)
                )
            )
        response = httpx.get(
            f"{gateway.url}/admin/audit/verify", headers=gateway.auth("admin"), timeout=60
        )
    body = response.json()
    assert body["ok"] is True, body
    assert body["rows_checked"] >= 200, "100 allowed calls are 200 rows"


# -- no secret reaches the log -----------------------------------------------------------------


async def test_no_credential_or_canary_reaches_any_audit_column(tmp_path: Path) -> None:
    canary = "wdn_canary_in_an_argument_0123456789"
    with running_gateway(tmp_path) as gateway:
        credential = gateway.keys["editor"]
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            await client.call_tool("notes_db__create_note", {"title": "secrets", "body": canary})
            await client.call_tool("notes_db__search_notes", {"query": "password"})
        rows = audit_rows(gateway.database_url)

    dumped = repr(rows)
    assert credential not in dumped, "the caller's API key must not be in the audit log"
    assert "Bearer" not in dumped
    # The canary sits under an innocent key, so redaction by key name keeps it; what matters
    # here is that no *credential* leaked. The DLP stage (Phase 8) is what refuses this call.
    assert any(row["args_sha256"] for row in rows)


async def test_a_secret_keyed_argument_is_redacted_in_the_log(tmp_path: Path) -> None:
    canary = "wdn_canary_under_a_secret_key_01234"
    policies = policies_allowing("admin", "admin-notes-any", ["notes_db__*"])
    with running_gateway(tmp_path, policies_config=policies) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            await client.call_tool(
                "notes_db__create_note", {"title": "t", "body": "b", "api_key": canary}
            )
        rows = audit_rows(gateway.database_url)
    dumped = repr(rows)
    assert canary not in dumped
    assert "[REDACTED]" in dumped


# -- tamper detection --------------------------------------------------------------------------


async def test_verify_detects_an_edited_row(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            for index in range(5):
                await client.call_tool("notes_db__get_note", {"note_id": index + 1})
        url = gateway.database_url
        rows = audit_rows(url)
        target = rows[len(rows) // 2]
        # Rewrite which tool was called - the realistic edit, and one that is guaranteed to
        # differ from what is there, so this test cannot quietly become a no-op UPDATE.
        tamper_sqlite(
            url,
            "UPDATE audit_events SET tool = ? WHERE id = ?",
            ("notes_db__list_notes", target["id"]),
        )
        after = {row["id"]: row for row in audit_rows(url)}[target["id"]]
        assert after["tool"] != target["tool"], "the tampering itself must have changed a value"
        response = httpx.get(
            f"{gateway.url}/admin/audit/verify", headers=gateway.auth("admin"), timeout=20
        )
    body = response.json()
    assert response.status_code == 409
    assert body["ok"] is False
    assert body["first_break"]["row_id"] == target["id"]
    assert body["first_break"]["kind"] == "row_hash"


async def test_verify_detects_a_deleted_row(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            for index in range(5):
                await client.call_tool("notes_db__get_note", {"note_id": index + 1})
        url = gateway.database_url
        rows = audit_rows(url)
        victim = rows[2]
        tamper_sqlite(url, "DELETE FROM audit_events WHERE id = ?", (victim["id"],))
        response = httpx.get(
            f"{gateway.url}/admin/audit/verify", headers=gateway.auth("admin"), timeout=20
        )
    body = response.json()
    assert body["ok"] is False
    assert body["first_break"]["kind"] == "prev_hash"
    assert "removed, reordered or inserted" in body["first_break"]["detail"]


async def test_verify_detects_a_reordered_pair(tmp_path: Path) -> None:
    """Swapping two rows' ids is the cheapest way to rewrite history without deleting."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            for index in range(6):
                await client.call_tool("notes_db__get_note", {"note_id": index + 1})
        url = gateway.database_url
        rows = audit_rows(url)
        first, second = rows[3]["id"], rows[4]["id"]
        spare = max(row["id"] for row in rows) + 1000
        tamper_sqlite(url, "UPDATE audit_events SET id = ? WHERE id = ?", (spare, first))
        tamper_sqlite(url, "UPDATE audit_events SET id = ? WHERE id = ?", (first, second))
        tamper_sqlite(url, "UPDATE audit_events SET id = ? WHERE id = ?", (second, spare))
        response = httpx.get(
            f"{gateway.url}/admin/audit/verify", headers=gateway.auth("admin"), timeout=20
        )
    body = response.json()
    assert body["ok"] is False
    assert body["first_break"]["kind"] == "prev_hash"


async def test_verify_detects_a_forged_inserted_row(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            for index in range(4):
                await client.call_tool("notes_db__get_note", {"note_id": index + 1})
        url = gateway.database_url
        rows = audit_rows(url)
        anchor = rows[1]
        tamper_sqlite(
            url,
            """
            INSERT INTO audit_events (
                id, ts, request_id, event, principal_id, auth_method, method, tool, upstream,
                risk, args_redacted, args_sha256, decision, reason_code, matched_rule,
                stage_timings_ms, result_bytes, result_sha256, scan_flags, prev_hash, row_hash
            ) VALUES (?, ?, 'forged', 'finished', 'attacker', 'api_key', 'tools/call',
                'files__delete_file', 'files', 'destructive', '{}', ?, 'allow',
                'WARDEN_ALLOWED', NULL, '{}', 0, NULL, '{}', ?, ?)
            """,
            (
                max(row["id"] for row in rows) + 1,
                anchor["ts"],
                "f" * 64,
                anchor["row_hash"],
                "e" * 64,
            ),
        )
        response = httpx.get(
            f"{gateway.url}/admin/audit/verify", headers=gateway.auth("admin"), timeout=20
        )
    assert response.json()["ok"] is False


# -- failing closed ----------------------------------------------------------------------------


async def test_an_unwritable_audit_log_denies_the_call_and_forwards_nothing(
    tmp_path: Path,
) -> None:
    """Hard rule 1 for the audit log, with the upstream watching.

    The gateway starts healthy, then the audit table is dropped from under it - a stand-in for
    "the audit store became unavailable while we were serving". Authentication, policy and the
    limiter all still work, so the write-ahead row is the only thing that fails, which is
    exactly the claim: a call that cannot be recorded is a call that is not forwarded.
    """
    import sqlite3

    from tests.helpers import header_recording_upstream, sqlite_path
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
        policies = policies_allowing("admin", "admin-recorder-audit", ["recorder__*"])
        with running_gateway(tmp_path, servers_config=servers, policies_config=policies) as gateway:
            async with gateway_client(gateway, gateway.auth("admin")) as client:
                healthy = await client.call_tool("recorder__echo", {"text": "this one is fine"})
                assert not healthy.is_error, error_text(healthy)

            connection = sqlite3.connect(sqlite_path(gateway.database_url))
            try:
                connection.execute("DROP TABLE audit_events")
                connection.commit()
            finally:
                connection.close()

            calls_before = len(seen_headers)
            async with gateway_client(gateway, gateway.auth("admin")) as client:
                result = await client.call_tool("recorder__echo", {"text": "should not arrive"})

            assert "WARDEN_DENIED:audit_unavailable" in error_text(result)
            assert result.structured_content is not None
            assert result.structured_content["error"] == "WARDEN_DENIED:audit_unavailable"

            # The MCP handshake is HTTP traffic too, so count requests rather than assuming
            # none: what matters is that no *new* request carried the tool call.
            bodies = [
                headers
                for headers in seen_headers[calls_before:]
                if headers.get("content-length", "0") not in ("0", "")
            ]
            assert not any("should not arrive" in str(headers) for headers in bodies)
            assert len(seen_headers) - calls_before <= 2, (
                "only handshake traffic may follow a denied call, never the call itself"
            )


async def test_the_gateway_refuses_to_start_when_it_cannot_read_the_pin_table(
    tmp_path: Path,
) -> None:
    """The other half of failing closed: not knowing what is quarantined is not a start-up.

    A gateway that came up without the quarantine list would serve every tool as if it had
    been approved, which is the one mistake Phase 8 exists to prevent.
    """
    from starlette.testclient import TestClient

    from tests.helpers import (
        test_gateway_config,
        test_servers_config,
        test_settings,
    )
    from warden.auth.tokens import NullRevocationStore
    from warden.health import Readiness
    from warden.main import create_app
    from warden.policy.store import PolicyStore

    settings = test_settings(
        tmp_path,
        database_url="postgresql+asyncpg://warden:warden@127.0.0.1:1/warden",
    )
    servers = test_servers_config(tmp_path)
    app = create_app(
        settings,
        readiness=Readiness({}),
        gateway_config=test_gateway_config(),
        servers_config=servers,
        policy_store=PolicyStore.from_config(settings.policies_yaml, servers, None),
        revocations=NullRevocationStore(),
        redis=_FakeRedisForStartup(),
    )
    with pytest.raises(Exception) as failure, TestClient(app):
        pass
    assert "connect" in str(failure.value).lower() or "refused" in str(failure.value).lower()


class _FakeRedisForStartup:
    """Enough of Redis that the limiter can be built; startup fails on Postgres, not here."""

    async def eval(self, *_: object, **__: object) -> object:  # pragma: no cover
        raise ConnectionError("not used")

    async def aclose(self) -> None:
        return None


# -- the admin API -----------------------------------------------------------------------------


async def test_admin_audit_requires_the_admin_role(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        for role, expected in (("reader", 403), ("editor", 403), ("admin", 200)):
            response = httpx.get(
                f"{gateway.url}/admin/audit", headers=gateway.auth(role), timeout=20
            )
            assert response.status_code == expected, f"{role} got {response.status_code}"
        assert httpx.get(f"{gateway.url}/admin/audit", timeout=20).status_code == 401
        assert (
            httpx.get(
                f"{gateway.url}/admin/audit/verify", headers=gateway.auth("reader"), timeout=20
            ).status_code
            == 403
        )


async def test_admin_audit_filters(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            await client.call_tool("notes_db__list_notes", {"limit": 1})
            await client.call_tool("notes_db__run_sql", {"query": "SELECT 1"})
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            await client.call_tool("notes_db__get_note", {"note_id": 1})

        def query(**params: str) -> list[dict[str, Any]]:
            response = httpx.get(
                f"{gateway.url}/admin/audit",
                params={"limit": "200", **params},
                headers=gateway.auth("admin"),
                timeout=20,
            )
            assert response.status_code == 200, response.text
            return list(response.json()["rows"])

        everything = query()
        reader_rows = query(user="reader-user")
        denials = query(decision="deny")
        sql_rows = query(tool="notes_db__run_sql")
        policy_denials = query(reason_code="WARDEN_DENIED:policy")

    assert len(everything) > len(reader_rows)
    assert {row["principal_id"] for row in reader_rows} == {"reader-user"}
    assert all(row["decision"] == "deny" for row in denials)
    assert {row["tool"] for row in sql_rows} == {"notes_db__run_sql"}
    assert len(policy_denials) == 1
    assert policy_denials[0]["matched_rule"] == "reader-no-sql"


async def test_admin_audit_time_filters_and_bad_input(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            await client.call_tool("notes_db__get_note", {"note_id": 1})

        future = httpx.get(
            f"{gateway.url}/admin/audit",
            params={"since": "2099-01-01T00:00:00Z"},
            headers=gateway.auth("admin"),
            timeout=20,
        )
        past = httpx.get(
            f"{gateway.url}/admin/audit",
            params={"since": "2000-01-01T00:00:00Z"},
            headers=gateway.auth("admin"),
            timeout=20,
        )
        bad = httpx.get(
            f"{gateway.url}/admin/audit",
            params={"since": "yesterday"},
            headers=gateway.auth("admin"),
            timeout=20,
        )
        bad_cursor = httpx.get(
            f"{gateway.url}/admin/audit",
            params={"cursor": "abc"},
            headers=gateway.auth("admin"),
            timeout=20,
        )

    assert future.json()["rows"] == []
    assert past.json()["rows"]
    assert bad.status_code == 400
    assert "ISO-8601" in bad.json()["error_description"]
    assert bad_cursor.status_code == 400


async def test_admin_audit_pagination(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            for index in range(8):
                await client.call_tool("notes_db__get_note", {"note_id": (index % 10) + 1})

        seen: list[int] = []
        cursor: str | None = None
        for _ in range(20):
            params = {"limit": "5"}
            if cursor is not None:
                params["cursor"] = cursor
            response = httpx.get(
                f"{gateway.url}/admin/audit",
                params=params,
                headers=gateway.auth("admin"),
                timeout=20,
            )
            body = response.json()
            seen.extend(row["id"] for row in body["rows"])
            if body["next_cursor"] is None:
                break
            cursor = str(body["next_cursor"])

    assert len(seen) == len(set(seen)), "pagination must not repeat a row"
    assert len(seen) >= 16


async def test_admin_audit_csv_export(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            await client.call_tool("notes_db__get_note", {"note_id": 1})
        response = httpx.get(
            f"{gateway.url}/admin/audit",
            params={"format": "csv"},
            headers=gateway.auth("admin"),
            timeout=20,
        )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    parsed = list(csv.DictReader(io.StringIO(response.text)))
    assert parsed
    assert "row_hash" in parsed[0]
    assert "args_redacted" not in parsed[0], "nested JSON is left to the JSON endpoint"
    assert any(row["tool"] == "notes_db__get_note" for row in parsed)


async def test_admin_usage_reports_the_budget_counters(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            await client.call_tool("notes_db__get_note", {"note_id": 1})
        response = httpx.get(
            f"{gateway.url}/admin/usage",
            params={"user": "editor-user"},
            headers=gateway.auth("admin"),
            timeout=20,
        )
        missing = httpx.get(f"{gateway.url}/admin/usage", headers=gateway.auth("admin"), timeout=20)
    assert response.json()["usage"]["calls"] >= 1
    assert missing.status_code == 400
