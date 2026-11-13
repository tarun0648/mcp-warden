"""Approvals end to end: the upstream must run exactly once, and only when a human says so."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from tests.helpers import (
    audit_rows,
    decide_approval,
    error_text,
    gateway_client,
    list_approvals,
    payload,
    running_gateway,
    wait_for_approval,
)

pytestmark = pytest.mark.integration

#: Long enough that a test can decide mid-wait, short enough not to drag.
WAITING = {"approval": {"wait_seconds": 8.0, "expiry_seconds": 300.0}}
#: Returns PENDING almost at once, for the retry tests.
NO_WAIT = {"approval": {"wait_seconds": 0.3, "expiry_seconds": 300.0}}


def call_rows(url: str, tool: str) -> list[dict[str, object]]:
    """Pipeline rows for one tool.

    Filtered by method as well as tool: approval lifecycle rows carry the same tool name, and
    counting them as forwarded calls would make "exactly once" meaningless.
    """
    return [row for row in audit_rows(url) if row["tool"] == tool and row["method"] == "tools/call"]


async def seed_file(gateway: object, name: str = "doomed.md") -> None:
    async with gateway_client(gateway, gateway.auth("editor")) as client:  # type: ignore[attr-defined]
        payload(await client.call_tool("files__write_file", {"path": name, "content": "x"}))


# -- the happy path ----------------------------------------------------------------------------


async def test_a_destructive_call_waits_and_runs_once_when_approved(tmp_path: Path) -> None:
    """The headline demo: editor deletes, admin approves, the delete happens exactly once."""
    with running_gateway(tmp_path, gateway_overrides=WAITING) as gateway:
        await seed_file(gateway)
        assert (tmp_path / "sandbox" / "doomed.md").exists()

        async def approve_when_it_appears() -> str:
            request = await wait_for_approval(gateway)
            response = decide_approval(gateway, request["id"], approve=True)
            assert response.status_code == 200, response.text
            return str(request["id"])

        approver = asyncio.create_task(approve_when_it_appears())
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        approval_id = await approver

        deletes = call_rows(gateway.database_url, "files__delete_file")

    assert not result.is_error, error_text(result)
    assert not (tmp_path / "sandbox" / "doomed.md").exists(), "the delete must have run"

    assert [row["event"] for row in deletes] == ["started", "finished"], (
        "exactly one forwarded call"
    )
    flags = json.loads(deletes[0]["scan_flags"])
    assert flags["approval"]["id"] == approval_id
    assert flags["approval"]["status"] == "consumed"


async def test_the_queue_shows_the_approver_what_they_are_deciding(tmp_path: Path) -> None:
    with running_gateway(tmp_path, gateway_overrides=WAITING) as gateway:
        await seed_file(gateway)
        caller = asyncio.create_task(_call_delete(gateway, "doomed.md"))
        request = await wait_for_approval(gateway)
        decide_approval(gateway, request["id"], approve=False)
        await caller

    assert request["tool"] == "files__delete_file"
    assert request["principal_id"] == "editor-user"
    assert request["risk"] == "destructive"
    assert request["args_redacted"] == {"path": "doomed.md"}
    assert len(request["args_sha256"]) == 64


async def _call_delete(gateway: object, path: str) -> object:
    async with gateway_client(gateway, gateway.auth("editor")) as client:  # type: ignore[attr-defined]
        return await client.call_tool("files__delete_file", {"path": path})


# -- denial ------------------------------------------------------------------------------------


async def test_a_denied_call_is_refused_and_never_forwarded(tmp_path: Path) -> None:
    with running_gateway(tmp_path, gateway_overrides=WAITING) as gateway:
        await seed_file(gateway)

        async def deny_when_it_appears() -> None:
            request = await wait_for_approval(gateway)
            assert (
                decide_approval(
                    gateway, request["id"], approve=False, reason="not today"
                ).status_code
                == 200
            )

        denier = asyncio.create_task(deny_when_it_appears())
        result = await _call_delete(gateway, "doomed.md")
        await denier
        deletes = call_rows(gateway.database_url, "files__delete_file")

    assert "WARDEN_DENIED:approval_denied" in error_text(result)
    assert (tmp_path / "sandbox" / "doomed.md").exists(), "the delete must not have run"
    assert [row["event"] for row in deletes] == ["denied"], (
        "a denied approval must leave no started row"
    )


# -- timeout, then retry -----------------------------------------------------------------------


async def test_an_undecided_call_returns_pending_then_succeeds_once_on_retry(
    tmp_path: Path,
) -> None:
    """Pending is not a denial: the caller is told to come back with the same arguments."""
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        await seed_file(gateway)

        async with gateway_client(gateway, gateway.auth("editor")) as client:
            first = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        assert "WARDEN_PENDING:approval" in error_text(first)
        assert first.structured_content is not None
        approval_id = first.structured_content["approval_id"]
        assert approval_id

        # Still waiting, so the file is untouched.
        assert (tmp_path / "sandbox" / "doomed.md").exists()

        assert decide_approval(gateway, approval_id, approve=True).status_code == 200

        async with gateway_client(gateway, gateway.auth("editor")) as client:
            second = await client.call_tool("files__delete_file", {"path": "doomed.md"})
            assert not second.is_error, error_text(second)
            # And a third attempt is refused: approvals are single-use.
            third = await client.call_tool("files__delete_file", {"path": "doomed.md"})

    assert not (tmp_path / "sandbox" / "doomed.md").exists()
    assert third.is_error
    assert "WARDEN_DENIED:approval_denied" in error_text(third)
    assert "single-use" in error_text(third)


async def test_retrying_while_still_pending_reuses_the_same_approval(
    tmp_path: Path,
) -> None:
    """A caller that retries must not fill the queue with duplicates."""
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        await seed_file(gateway)
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            first = await client.call_tool("files__delete_file", {"path": "doomed.md"})
            second = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        queue = list_approvals(gateway)

    assert first.structured_content is not None and second.structured_content is not None
    assert first.structured_content["approval_id"] == second.structured_content["approval_id"]
    assert len(queue) == 1


# -- replay ------------------------------------------------------------------------------------


async def test_an_approval_cannot_be_reused_for_different_arguments(
    tmp_path: Path,
) -> None:
    """Approve deleting one file, then try to delete another with the same approval."""
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        await seed_file(gateway, "keep.md")
        await seed_file(gateway, "doomed.md")

        async with gateway_client(gateway, gateway.auth("editor")) as client:
            pending = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        approval_id = pending.structured_content["approval_id"]  # type: ignore[index]
        decide_approval(gateway, approval_id, approve=True)

        async with gateway_client(gateway, gateway.auth("editor")) as client:
            other = await client.call_tool("files__delete_file", {"path": "keep.md"})

    assert "WARDEN_PENDING:approval" in error_text(other), (
        "a different path is a different call, so it needs its own approval"
    )
    assert (tmp_path / "sandbox" / "keep.md").exists()
    assert (tmp_path / "sandbox" / "doomed.md").exists(), "the approved delete was not retried"


async def test_an_approval_cannot_be_used_by_a_different_caller(tmp_path: Path) -> None:
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        await seed_file(gateway)

        async with gateway_client(gateway, gateway.auth("editor")) as client:
            pending = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        approval_id = pending.structured_content["approval_id"]  # type: ignore[index]
        decide_approval(gateway, approval_id, approve=True)

        # admin asks for the same delete: the approval is bound to editor-user.
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            theirs = await client.call_tool("files__delete_file", {"path": "doomed.md"})

    assert "WARDEN_PENDING:approval" in error_text(theirs)
    assert (tmp_path / "sandbox" / "doomed.md").exists()


# -- separation of duties ----------------------------------------------------------------------


async def test_the_requester_cannot_approve_their_own_call(tmp_path: Path) -> None:
    """The admin role asks for the delete, so the admin role may not approve it."""
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        await seed_file(gateway)
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            pending = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        approval_id = pending.structured_content["approval_id"]  # type: ignore[index]

        response = decide_approval(gateway, approval_id, approve=True, role="admin")

        async with gateway_client(gateway, gateway.auth("admin")) as client:
            retry = await client.call_tool("files__delete_file", {"path": "doomed.md"})

    assert response.status_code == 409
    assert "may not approve their own" in response.json()["message"]
    assert "WARDEN_PENDING:approval" in error_text(retry)
    assert (tmp_path / "sandbox" / "doomed.md").exists()


# -- access control ----------------------------------------------------------------------------


async def test_the_approval_api_is_admin_only(tmp_path: Path) -> None:
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        await seed_file(gateway)
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            pending = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        approval_id = pending.structured_content["approval_id"]  # type: ignore[index]

        for role in ("reader", "editor"):
            assert (
                httpx.get(
                    f"{gateway.url}/admin/approvals", headers=gateway.auth(role), timeout=20
                ).status_code
                == 403
            ), role
            assert decide_approval(gateway, approval_id, role=role).status_code == 403, role
        assert httpx.get(f"{gateway.url}/admin/approvals", timeout=20).status_code == 401

        async with gateway_client(gateway, gateway.auth("editor")) as client:
            still_pending = await client.call_tool("files__delete_file", {"path": "doomed.md"})
    assert "WARDEN_PENDING:approval" in error_text(still_pending)


async def test_the_approval_page_is_served_and_needs_a_key(tmp_path: Path) -> None:
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        page = httpx.get(f"{gateway.url}/approvals", timeout=20)
        signed_in = httpx.post(
            f"{gateway.url}/approvals/login",
            data={"api_key": gateway.keys["admin"]},
            timeout=20,
            follow_redirects=False,
        )
        refused = httpx.post(
            f"{gateway.url}/approvals/login",
            data={"api_key": gateway.keys["reader"]},
            timeout=20,
        )
    assert page.status_code == 200
    assert "Admin API key" in page.text
    assert signed_in.status_code == 303
    assert "HttpOnly" in signed_in.headers["set-cookie"]
    assert refused.status_code == 401


# -- concurrency -------------------------------------------------------------------------------


async def test_two_approvers_at_once_produce_one_forwarded_call(tmp_path: Path) -> None:
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        await seed_file(gateway)
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            pending = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        approval_id = pending.structured_content["approval_id"]  # type: ignore[index]

        responses = await asyncio.gather(
            asyncio.to_thread(decide_approval, gateway, approval_id, approve=True),
            asyncio.to_thread(decide_approval, gateway, approval_id, approve=False),
        )
        accepted = [r for r in responses if r.status_code == 200]
        assert len(accepted) == 1, [r.json() for r in responses]

        async with gateway_client(gateway, gateway.auth("editor")) as client:
            retries = await asyncio.gather(
                *(client.call_tool("files__delete_file", {"path": "doomed.md"}) for _ in range(4))
            )
        rows = call_rows(gateway.database_url, "files__delete_file")

    forwarded = [row for row in rows if row["event"] == "started"]
    assert len(forwarded) <= 1, "the upstream must be reached at most once"
    successes = [r for r in retries if not r.is_error]
    assert len(successes) <= 1


# -- the non-destructive case ------------------------------------------------------------------


async def test_a_write_does_not_need_approval(tmp_path: Path) -> None:
    """The false-positive partner: only destructive tools stop for a human."""
    with running_gateway(tmp_path, gateway_overrides=WAITING) as gateway:
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            written = payload(
                await client.call_tool(
                    "files__write_file", {"path": "ordinary.md", "content": "fine"}
                )
            )
            read = payload(await client.call_tool("files__read_file", {"path": "ordinary.md"}))
            sql = payload(await client.call_tool("notes_db__run_sql", {"query": "SELECT 1 AS n"}))
        assert list_approvals(gateway) == [], "nothing should have been queued"
    assert written["path"] == "ordinary.md"
    assert read["content"] == "fine"
    assert sql["rows"] == [[1]]


async def test_a_policy_rule_can_waive_approval(tmp_path: Path) -> None:
    from tests.helpers import policies_allowing

    policies = policies_allowing(
        "editor",
        "editor-delete-waived",
        ["files__delete_file"],
        prepend=True,
        require_approval=False,
    )
    with running_gateway(tmp_path, gateway_overrides=WAITING, policies_config=policies) as gateway:
        await seed_file(gateway)
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            result = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        assert list_approvals(gateway) == []
    assert not result.is_error, error_text(result)
    assert not (tmp_path / "sandbox" / "doomed.md").exists()


# -- the audit trail ---------------------------------------------------------------------------


async def test_the_whole_approval_lifecycle_is_in_the_audit_log(tmp_path: Path) -> None:
    """Approvals are the one decision a human makes, so they belong in the hash-chained log."""
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        await seed_file(gateway)
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            pending = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        approval_id = pending.structured_content["approval_id"]  # type: ignore[index]
        decide_approval(gateway, approval_id, approve=True, reason="looks fine")
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            done = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        assert not done.is_error, error_text(done)

        verify = httpx.get(
            f"{gateway.url}/admin/audit/verify", headers=gateway.auth("admin"), timeout=30
        )
        rows = audit_rows(gateway.database_url)

    events = [row["event"] for row in rows if row["method"] == "approvals/decide"]
    assert "approval_requested" in events
    assert "approval_approved" in events
    assert "approval_consumed" in events

    decided = next(row for row in rows if row["event"] == "approval_approved")
    assert decided["principal_id"] == "admin-user", "the decider is recorded"
    flags = json.loads(decided["scan_flags"])
    assert flags["approval"]["requested_by"] == "editor-user"
    assert flags["approval"]["reason"] == "looks fine"
    assert decided["tool"] == "files__delete_file"

    assert verify.status_code == 200
    assert verify.json()["ok"] is True, "approval rows must not break the chain"


async def test_a_denied_approval_is_recorded_too(tmp_path: Path) -> None:
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        await seed_file(gateway)
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            pending = await client.call_tool("files__delete_file", {"path": "doomed.md"})
        approval_id = pending.structured_content["approval_id"]  # type: ignore[index]
        decide_approval(gateway, approval_id, approve=False, reason="no")
        rows = audit_rows(gateway.database_url)
    assert any(row["event"] == "approval_denied" for row in rows)


async def test_no_credential_reaches_an_approval_row(tmp_path: Path) -> None:
    with running_gateway(tmp_path, gateway_overrides=NO_WAIT) as gateway:
        credential = gateway.keys["editor"]
        await seed_file(gateway)
        async with gateway_client(gateway, gateway.auth("editor")) as client:
            await client.call_tool("files__delete_file", {"path": "doomed.md"})
        rows = [row for row in audit_rows(gateway.database_url) if "approval" in row["event"]]
        queue = list_approvals(gateway)
    assert rows
    assert credential not in repr(rows)
    assert credential not in repr(queue)
