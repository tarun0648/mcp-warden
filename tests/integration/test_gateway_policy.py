"""The policy engine through the real gateway: what each role can see and call."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from tests.helpers import error_text, gateway_client, payload, running_gateway

pytestmark = pytest.mark.integration


async def test_each_role_sees_a_different_tool_list(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            reader_tools = {tool.name for tool in (await client.list_tools()).tools}
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            editor_tools = {tool.name for tool in (await client.list_tools()).tools}
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            admin_tools = {tool.name for tool in (await client.list_tools()).tools}

    assert reader_tools == {
        "notes_db__list_notes",
        "notes_db__get_note",
        "notes_db__search_notes",
        "files__list_files",
        "files__read_file",
    }
    assert "files__delete_file" not in reader_tools
    assert "notes_db__run_sql" not in reader_tools
    assert "files__delete_file" in editor_tools
    assert reader_tools < editor_tools
    assert editor_tools == admin_tools


async def test_a_reader_cannot_see_or_call_the_delete_tool(tmp_path: Path) -> None:
    """The demo case: hidden from the listing, and refused if called by name anyway."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert "files__delete_file" not in names
            result = await client.call_tool("files__delete_file", {"path": "a.md"})
    message = error_text(result)
    assert "WARDEN_DENIED:policy" in message
    assert result.structured_content is not None
    assert result.structured_content["error"] == "WARDEN_DENIED:policy"


async def test_a_denied_tool_is_never_forwarded(tmp_path: Path) -> None:
    """Proof the upstream never ran: the file an editor created is still there."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            payload(
                await client.call_tool("files__write_file", {"path": "keep.md", "content": "x"})
            )
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            denied = await client.call_tool("files__delete_file", {"path": "keep.md"})
    assert "WARDEN_DENIED:policy" in error_text(denied)
    assert (tmp_path / "sandbox" / "keep.md").read_text() == "x"


async def test_an_explicit_deny_rule_beats_the_role_that_allows(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            result = await client.call_tool("notes_db__run_sql", {"query": "SELECT 1"})
    assert result.structured_content is not None
    assert result.structured_content["matched_rule"] == "reader-no-sql"


async def test_an_argument_constraint_blocks_traversal_at_the_gateway(tmp_path: Path) -> None:
    """The gateway refuses before the files server's own sandbox check ever runs."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool(
                "files__write_file", {"path": "../escaped.md", "content": "pwned"}
            )
    assert "WARDEN_DENIED:policy" in error_text(result)
    assert not (tmp_path / "escaped.md").exists()


async def test_a_long_argument_is_refused_by_the_constraint(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool("notes_db__run_sql", {"query": "SELECT " + "1," * 3000})
    assert "WARDEN_DENIED:policy" in error_text(result)
    assert "query" in error_text(result)


async def test_the_normal_case_still_works(tmp_path: Path) -> None:
    """Every security rule needs a no-false-positive partner."""
    with running_gateway(tmp_path) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            written = payload(
                await client.call_tool(
                    "files__write_file", {"path": "notes/ok.md", "content": "fine"}
                )
            )
            assert written["path"] == "notes/ok.md"
            sql = payload(
                await client.call_tool("notes_db__run_sql", {"query": "SELECT COUNT(*) FROM notes"})
            )
            assert sql["rows"] == [[10]]
            read = payload(await client.call_tool("files__read_file", {"path": "notes/ok.md"}))
            assert read["content"] == "fine"


# -- admin API ---------------------------------------------------------------------------------


async def test_admin_endpoints_require_the_admin_role(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        for role, expected in (("reader", 403), ("editor", 403), ("admin", 200)):
            response = httpx.get(
                f"{gateway.url}/admin/policy", headers=gateway.auth(role), timeout=10
            )
            assert response.status_code == expected, f"{role} got {response.status_code}"


async def test_admin_endpoints_require_a_credential(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        assert httpx.get(f"{gateway.url}/admin/policy", timeout=10).status_code == 401


async def test_policy_status_reports_the_rules(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        response = httpx.get(
            f"{gateway.url}/admin/policy", headers=gateway.auth("admin"), timeout=10
        )
    body = response.json()
    assert "reader" in body["policy"]["roles"]
    assert body["policy"]["rule_count"] > 0
    assert body["rules"]["tool_risk"]["files__delete_file"] == "destructive"


async def test_reload_takes_effect_on_the_next_call(tmp_path: Path) -> None:
    """A policy change must not need a restart - and must be visible immediately."""
    policies_path = tmp_path / "policies.yaml"
    policies_path.write_text(
        "roles:\n"
        "  reader:\n    rules:\n      - {id: r-read, effect: allow, tools: ['notes_db__list_notes']}\n"
        "  admin:\n    rules:\n      - {id: a-all, effect: allow, tools: ['notes_db__*']}\n"
    )
    with running_gateway(
        tmp_path, settings_overrides={"config_dir": tmp_path}, policies_config=None
    ) as gateway:
        async with gateway_client(gateway, gateway.auth("reader")) as client:
            assert (await client.call_tool("notes_db__get_note", {"note_id": 1})).is_error

        policies_path.write_text(
            "roles:\n"
            "  reader:\n    rules:\n"
            "      - {id: r-read, effect: allow, tools: ['notes_db__list_notes', 'notes_db__get_note']}\n"
            "  admin:\n    rules:\n      - {id: a-all, effect: allow, tools: ['notes_db__*']}\n"
        )
        response = httpx.post(
            f"{gateway.url}/admin/reload", headers=gateway.auth("admin"), timeout=10
        )
        assert response.status_code == 200
        assert response.json()["changed"] is True

        async with gateway_client(gateway, gateway.auth("reader")) as client:
            result = await client.call_tool("notes_db__get_note", {"note_id": 1})
            assert not result.is_error, error_text(result)


async def test_a_broken_reload_is_rejected_and_the_old_policy_still_enforces(
    tmp_path: Path,
) -> None:
    policies_path = tmp_path / "policies.yaml"
    policies_path.write_text(
        "roles:\n"
        "  reader:\n    rules:\n      - {id: r-read, effect: allow, tools: ['notes_db__list_notes']}\n"
        "  admin:\n    rules:\n      - {id: a-all, effect: allow, tools: ['notes_db__*']}\n"
    )
    with running_gateway(
        tmp_path, settings_overrides={"config_dir": tmp_path}, policies_config=None
    ) as gateway:
        policies_path.write_text("roles: {not a mapping\n")
        response = httpx.post(
            f"{gateway.url}/admin/reload", headers=gateway.auth("admin"), timeout=10
        )
        assert response.status_code == 409
        assert response.json()["changed"] is False
        assert "rejected" in response.json()["message"]

        async with gateway_client(gateway, gateway.auth("reader")) as client:
            allowed = await client.call_tool("notes_db__list_notes", {"limit": 1})
            denied = await client.call_tool("notes_db__delete_note", {"note_id": 1})
    assert not allowed.is_error, "the old policy must still allow what it allowed"
    assert denied.is_error, "the old policy must still deny what it denied"


async def test_upstream_status_is_admin_only(tmp_path: Path) -> None:
    with running_gateway(tmp_path) as gateway:
        response = httpx.get(
            f"{gateway.url}/admin/upstreams", headers=gateway.auth("admin"), timeout=10
        )
        assert response.status_code == 200
        states = {entry["name"]: entry["state"] for entry in response.json()["upstreams"]}
        assert states == {"notes_db": "up", "files": "up"}
        assert (
            httpx.get(
                f"{gateway.url}/admin/upstreams", headers=gateway.auth("reader"), timeout=10
            ).status_code
            == 403
        )
