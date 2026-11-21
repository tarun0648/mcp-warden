"""The console's building blocks: sessions, filters, jobs, and CSP-clean templates."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from warden.console.playground import (
    AUTH_METHOD,
    Job,
    JobStore,
    console_principal,
    suggested_arguments,
)
from warden.console.web import (
    ADMIN_ROLE,
    NAV,
    TEMPLATE_DIR,
    ConsoleSessions,
    _ago,
    _tone,
    _visible,
    build_environment,
)

pytestmark = pytest.mark.unit


# -- sessions ----------------------------------------------------------------------------------


def test_a_session_remembers_roles_and_knows_an_admin() -> None:
    sessions = ConsoleSessions()
    token, session = sessions.create("alice", ("reader",))
    assert sessions.get(token) is session
    assert not session.is_admin
    _token, admin = sessions.create("root", (ADMIN_ROLE, "editor"))
    assert admin.is_admin


def test_tokens_and_csrf_tokens_are_unguessable_and_distinct() -> None:
    sessions = ConsoleSessions()
    first_token, first = sessions.create("a", ("reader",))
    second_token, second = sessions.create("a", ("reader",))
    assert first_token != second_token
    assert first.csrf_token != second.csrf_token
    assert first_token != first.csrf_token
    assert len(first_token) >= 40


def test_an_expired_session_is_gone() -> None:
    sessions = ConsoleSessions()
    token, session = sessions.create("a", ("reader",))
    session.created_at = time.time() - 9 * 3600
    assert sessions.get(token) is None
    assert len(sessions) == 0


@pytest.mark.parametrize("token", [None, "", "not-a-token"])
def test_an_unknown_token_is_no_session(token: str | None) -> None:
    assert ConsoleSessions().get(token) is None


def test_sign_out_destroys_the_session() -> None:
    sessions = ConsoleSessions()
    token, _session = sessions.create("a", ("reader",))
    sessions.destroy(token)
    assert sessions.get(token) is None


# -- the navigation and the guards agree -------------------------------------------------------


def test_the_admin_sections_are_marked_admin_only() -> None:
    admin_only = {key for key, _label, _path, admin in NAV if admin}
    assert admin_only == {"tools", "keys", "policy"}


# -- display filters -------------------------------------------------------------------------


def test_visible_makes_invisible_characters_visible_but_keeps_line_breaks() -> None:
    text = "line one\nline\u200b two\u202e"
    rendered = _visible(text)
    assert "\n" in rendered
    assert "<U+200B>" in rendered
    assert "<U+202E>" in rendered
    assert "\u200b" not in rendered and "\u202e" not in rendered


def test_visible_is_bounded() -> None:
    assert _visible("x" * 5000, 100).endswith("...")
    assert len(_visible("x" * 5000, 100)) == 103


@pytest.mark.parametrize(
    ("value", "tone"),
    [
        ("allow", "ok"),
        ("WARDEN_ALLOWED", "ok"),
        ("WARDEN_DENIED:policy", "bad"),
        ("WARDEN_PENDING:approval", "warn"),
        ("quarantined", "bad"),
        ("pinned", "ok"),
        ("up", "ok"),
        ("down", "bad"),
        ("something else", "neutral"),
        (None, "neutral"),
    ],
)
def test_tone(value: Any, tone: str) -> None:
    assert _tone(value) == tone


def test_ago() -> None:
    now = datetime.now(UTC)
    assert _ago((now - timedelta(seconds=30)).isoformat()).endswith("s ago")
    assert _ago((now - timedelta(minutes=5)).isoformat()) == "5 min ago"
    assert _ago((now + timedelta(minutes=5, seconds=30)).isoformat()) == "in 5 min"
    assert _ago("not a date") == ""


def test_autoescape_is_on_for_the_console_environment() -> None:
    template = build_environment().from_string("{{ value }}")
    assert template.render(value="<script>") == "&lt;script&gt;"


def test_a_misspelt_variable_fails_loudly() -> None:
    from jinja2 import UndefinedError

    with pytest.raises(UndefinedError):
        build_environment().from_string("{{ nope.attr }}").render()


# -- templates must be CSP-clean, or the CSP breaks the page ---------------------------------


def templates() -> dict[str, str]:
    """Each template as it can reach the browser: Jinja comments are never rendered."""
    return {
        path.name: re.sub(r"\{#.*?#\}", "", path.read_text(), flags=re.S)
        for path in TEMPLATE_DIR.glob("*.html")
    }


def test_there_are_console_templates_to_check() -> None:
    assert len(templates()) >= 15


def test_no_console_template_has_inline_style_script_or_handlers() -> None:
    for name, text in templates().items():
        assert "style=" not in text, name
        assert "<style" not in text, name
        for match in re.finditer(r"<script\b([^>]*)>", text):
            assert "src=" in match.group(1), f"{name}: inline <script>"
        assert not re.search(r"\son[a-z]+\s*=", text), f"{name}: inline event handler"


def test_no_console_template_disables_escaping() -> None:
    for name, text in templates().items():
        assert "|safe" not in text.replace(" ", ""), name
        assert "autoescape false" not in text, name
        assert "Markup(" not in text, name


def test_every_form_that_posts_carries_the_csrf_token() -> None:
    """Except sign-in, which has no session yet."""
    for name, text in templates().items():
        for form in re.finditer(r"<form\b[^>]*>.*?</form>", text, flags=re.S):
            body = form.group(0)
            posts = 'method="post"' in body.split(">", 1)[0] or "hx-post=" in body.split(">", 1)[0]
            if posts and "/login" not in body:
                assert "csrf_field" in body, f"{name}: a POST form without the CSRF token"


def test_htmx_is_told_not_to_evaluate_or_inject_styles() -> None:
    head = templates()["_head.html"]
    assert '"allowEval": false' in head
    assert '"allowScriptTags": false' in head
    assert '"includeIndicatorStyles": false' in head
    assert 'integrity="sha384-' in head


# -- playground ------------------------------------------------------------------------------


def test_a_console_principal_is_marked_as_coming_from_the_console() -> None:
    principal = console_principal("admin-user", "reader")
    assert principal.auth_method == AUTH_METHOD == "console"
    assert principal.roles == ("reader",)
    assert principal.user_id == "admin-user"


def job(job_id: str, owner: str = "a", *, done: bool = True) -> Job:
    item = Job(id=job_id, owner=owner, tool="t", role="reader", arguments={})
    if done:
        item.finished_at = time.time()
    return item


def test_jobs_are_visible_only_to_their_owner() -> None:
    store = JobStore()
    store.add(job("1", "alice"))
    assert store.get("1", "alice") is not None
    assert store.get("1", "bob") is None
    assert store.recent("bob") == []


def test_old_finished_jobs_are_dropped_but_running_ones_are_kept() -> None:
    store = JobStore(limit=3)
    store.add(job("running", done=False))
    for index in range(5):
        store.add(job(f"done-{index}"))
    assert store.get("running", "a") is not None, "a call still in flight is never dropped"
    assert len(store) == 3
    assert store.get("done-4", "a") is not None
    assert store.get("done-0", "a") is None


def test_a_job_with_no_context_yet_reports_starting() -> None:
    assert job("x", done=False).outcome() == {"state": "starting"}


def test_suggested_arguments_use_defaults_and_blank_required_fields() -> None:
    schema = {
        "properties": {
            "path": {"type": "string", "default": "."},
            "limit": {"type": "integer"},
            "query": {"type": "string"},
            "cursor": {"type": "string", "default": None},
        },
        "required": ["query", "limit"],
    }
    assert suggested_arguments(schema) == {"path": ".", "query": "", "limit": 0}


@pytest.mark.parametrize("schema", [None, "x", {}, {"properties": None}])
def test_suggested_arguments_tolerate_a_malformed_schema(schema: Any) -> None:
    assert suggested_arguments(schema) == {}
