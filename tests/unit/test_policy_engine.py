"""The policy engine, driven mostly by one table of (role, tool, args, expected) rows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from warden.config import (
    PoliciesConfig,
    Risk,
    ServersConfig,
    load_policies_config,
    load_servers_config,
)
from warden.errors import ConfigError
from warden.pipeline import Principal
from warden.policy.engine import PolicyEngine
from warden.policy.store import PolicyStore

pytestmark = pytest.mark.unit

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def make_engine() -> PolicyEngine:
    """The engine over the policy the gateway actually ships."""
    return PolicyEngine(
        load_policies_config(CONFIG_DIR / "policies.yaml"),
        load_servers_config(CONFIG_DIR / "servers.yaml"),
    )


@pytest.fixture
def engine() -> PolicyEngine:
    return make_engine()


def who(*roles: str) -> Principal:
    return Principal(user_id="tester", roles=roles, auth_method="api_key", credential_id="testpfx")


# ----------------------------------------------------------------------------------------------
# The table. Each row is (roles, tool, arguments, expected allowed, expected rule id or None).
# ----------------------------------------------------------------------------------------------

CASES: list[tuple[tuple[str, ...], str, dict[str, Any], bool, str | None]] = [
    # --- reader: the read tools, and nothing else ---
    (("reader",), "notes_db__list_notes", {"limit": 5}, True, "reader-notes-read"),
    (("reader",), "notes_db__get_note", {"note_id": 1}, True, "reader-notes-read"),
    (("reader",), "notes_db__search_notes", {"query": "x"}, True, "reader-notes-read"),
    (("reader",), "files__list_files", {"path": "."}, True, "reader-files-read"),
    (("reader",), "files__read_file", {"path": "a.md"}, True, "reader-files-read"),
    (("reader",), "notes_db__create_note", {"title": "t", "body": "b"}, False, None),
    (("reader",), "notes_db__delete_note", {"note_id": 1}, False, None),
    (("reader",), "files__write_file", {"path": "a.md", "content": "x"}, False, None),
    (("reader",), "files__delete_file", {"path": "a.md"}, False, None),
    # A deny rule beats the absence of an allow, and names itself.
    (("reader",), "notes_db__run_sql", {"query": "SELECT 1"}, False, "reader-no-sql"),
    # A constraint the reader cannot satisfy.
    (("reader",), "files__read_file", {"path": "x" * 300}, False, "reader-files-read"),
    (("reader",), "files__read_file", {}, False, "reader-files-read"),
    # --- editor: reads, writes, SQL, deletes ---
    (("editor",), "notes_db__list_notes", {"limit": 5}, True, "editor-notes-read"),
    (("editor",), "notes_db__run_sql", {"query": "SELECT 1"}, True, "editor-notes-sql"),
    (("editor",), "notes_db__run_sql", {"query": "S" * 5000}, False, "editor-notes-sql"),
    (
        ("editor",),
        "notes_db__create_note",
        {"title": "t", "body": "b"},
        True,
        "editor-notes-create",
    ),
    (
        ("editor",),
        "notes_db__create_note",
        {"title": "t" * 200, "body": "b"},
        False,
        "editor-notes-create",
    ),
    (("editor",), "notes_db__delete_note", {"note_id": 3}, True, "editor-notes-delete"),
    (("editor",), "notes_db__delete_note", {"note_id": 0}, False, "editor-notes-delete"),
    (
        ("editor",),
        "files__write_file",
        {"path": "a.md", "content": "x"},
        True,
        "editor-files-write",
    ),
    (
        ("editor",),
        "files__write_file",
        {"path": "../a.md", "content": "x"},
        False,
        "editor-files-write",
    ),
    (
        ("editor",),
        "files__write_file",
        {"path": "a/../../x", "content": "x"},
        False,
        "editor-files-write",
    ),
    (
        ("editor",),
        "files__read_file",
        {"path": "notes/../../etc/passwd"},
        False,
        "editor-files-read",
    ),
    (("reader",), "files__read_file", {"path": "../../etc/passwd"}, False, "reader-files-read"),
    (("admin",), "files__read_file", {"path": "../../etc/passwd"}, False, "admin-all-files"),
    (("editor",), "files__delete_file", {"path": "../a.md"}, False, "editor-files-delete"),
    (
        ("editor",),
        "files__write_file",
        {"path": "a b.md", "content": "x"},
        False,
        "editor-files-write",
    ),
    (("editor",), "files__delete_file", {"path": "a.md"}, True, "editor-files-delete"),
    (("editor",), "evil__send_report", {"to": "x", "body": "y"}, False, None),
    # --- admin: everything on the two real upstreams, nothing on evil ---
    (("admin",), "files__delete_file", {"path": "a.md"}, True, "admin-all-files"),
    (("admin",), "notes_db__run_sql", {"query": "SELECT 1"}, True, "admin-all-notes"),
    (("admin",), "evil__get_weather", {"city": "x"}, False, None),
    # --- redteam: reaches the evil server on purpose ---
    (("redteam",), "evil__get_weather", {"city": "x"}, True, "redteam-evil"),
    (("redteam",), "evil__send_report", {"to": "x", "body": "y"}, True, "redteam-evil"),
    # --- unknown roles and tools ---
    ((), "files__read_file", {"path": "a.md"}, False, None),
    (("nosuchrole",), "files__read_file", {"path": "a.md"}, False, None),
    (("reader",), "files__no_such_tool", {}, False, None),
    (("reader",), "nosuchserver__read_file", {"path": "a.md"}, False, None),
    (("reader",), "read_file", {"path": "a.md"}, False, None),
    # --- combined roles: the union of what each grants ---
    (
        ("reader", "editor"),
        "files__write_file",
        {"path": "a.md", "content": "x"},
        True,
        "editor-files-write",
    ),
    # ...but a deny in one role still wins over an allow in another.
    (("reader", "editor"), "notes_db__run_sql", {"query": "SELECT 1"}, False, "reader-no-sql"),
    (("reader", "admin"), "notes_db__run_sql", {"query": "SELECT 1"}, False, "reader-no-sql"),
]


@pytest.mark.parametrize(("roles", "tool", "args", "allowed", "rule"), CASES)
def test_policy_table(
    engine: PolicyEngine,
    roles: tuple[str, ...],
    tool: str,
    args: dict[str, Any],
    allowed: bool,
    rule: str | None,
) -> None:
    decision = engine.evaluate(who(*roles) if roles else who(), tool, args)
    assert decision.allowed is allowed, f"{roles} {tool} {args}: {decision.reason}"
    if rule is not None:
        assert decision.rule_id == rule
    else:
        assert decision.rule_id is None


def test_the_table_covers_both_outcomes_in_quantity() -> None:
    """A table of only-allows or only-denies would prove little."""
    allows = sum(1 for case in CASES if case[3])
    denies = len(CASES) - allows
    assert len(CASES) >= 30
    assert allows >= 10 and denies >= 10


# ----------------------------------------------------------------------------------------------


def test_no_principal_is_denied(engine: PolicyEngine) -> None:
    decision = engine.evaluate(None, "files__read_file", {"path": "a.md"})
    assert decision.denied
    assert "not authenticated" in decision.reason


def test_unknown_role_says_so(engine: PolicyEngine) -> None:
    decision = engine.evaluate(who("ghost"), "files__read_file", {"path": "a.md"})
    assert decision.denied
    assert "no policy defines role" in decision.reason


def test_a_known_role_alongside_an_unknown_one_still_works(engine: PolicyEngine) -> None:
    decision = engine.evaluate(who("ghost", "reader"), "files__read_file", {"path": "a.md"})
    assert decision.allowed


def test_denial_reason_names_the_tool(engine: PolicyEngine) -> None:
    decision = engine.evaluate(who("reader"), "files__delete_file", {"path": "a.md"})
    assert "files__delete_file" in decision.reason


def test_constraint_failure_explains_itself(engine: PolicyEngine) -> None:
    decision = engine.evaluate(who("editor"), "files__write_file", {"path": "../x", "content": "y"})
    assert decision.denied
    assert "path" in decision.reason
    assert decision.failures


# -- risk and approval -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        ("files__read_file", Risk.READ),
        ("files__write_file", Risk.WRITE),
        ("files__delete_file", Risk.DESTRUCTIVE),
        ("notes_db__delete_note", Risk.DESTRUCTIVE),
        ("notes_db__list_notes", Risk.READ),
    ],
)
def test_risk_levels(engine: PolicyEngine, tool: str, expected: Risk) -> None:
    assert engine.risk_for(tool) is expected


def test_an_unknown_tool_is_treated_as_destructive(engine: PolicyEngine) -> None:
    """If we cannot tell what a tool does, we assume the worst."""
    assert engine.risk_for("whoknows__something") is Risk.DESTRUCTIVE
    assert engine.risk_for("notnamespaced") is Risk.DESTRUCTIVE


def test_destructive_tools_require_approval_by_default(engine: PolicyEngine) -> None:
    decision = engine.evaluate(who("editor"), "files__delete_file", {"path": "a.md"})
    assert decision.allowed
    assert decision.requires_approval is True
    assert decision.risk is Risk.DESTRUCTIVE


def test_non_destructive_tools_do_not_require_approval(engine: PolicyEngine) -> None:
    decision = engine.evaluate(who("editor"), "files__write_file", {"path": "a.md", "content": "x"})
    assert decision.allowed
    assert decision.requires_approval is False


def test_a_rule_can_waive_approval(servers_config: ServersConfig) -> None:
    policies = PoliciesConfig.model_validate(
        {
            "tool_risk": {"files__delete_file": "destructive"},
            "roles": {
                "ops": {
                    "rules": [
                        {
                            "id": "ops-delete-no-approval",
                            "effect": "allow",
                            "tools": ["files__delete_file"],
                            "require_approval": False,
                        }
                    ]
                }
            },
        }
    )
    decision = PolicyEngine(policies, servers_config).evaluate(
        who("ops"), "files__delete_file", {"path": "a.md"}
    )
    assert decision.allowed and decision.requires_approval is False


def test_a_rule_can_demand_approval_for_a_read(servers_config: ServersConfig) -> None:
    policies = PoliciesConfig.model_validate(
        {
            "roles": {
                "ops": {
                    "rules": [
                        {
                            "id": "ops-sql-approval",
                            "effect": "allow",
                            "tools": ["notes_db__run_sql"],
                            "require_approval": True,
                        }
                    ]
                }
            }
        }
    )
    decision = PolicyEngine(policies, servers_config).evaluate(
        who("ops"), "notes_db__run_sql", {"query": "SELECT 1"}
    )
    assert decision.allowed and decision.requires_approval is True


def test_a_rule_can_override_risk(servers_config: ServersConfig) -> None:
    policies = PoliciesConfig.model_validate(
        {
            "roles": {
                "ops": {
                    "rules": [
                        {
                            "id": "ops-sql-destructive",
                            "effect": "allow",
                            "tools": ["notes_db__run_sql"],
                            "risk": "destructive",
                        }
                    ]
                }
            }
        }
    )
    decision = PolicyEngine(policies, servers_config).evaluate(
        who("ops"), "notes_db__run_sql", {"query": "SELECT 1"}
    )
    assert decision.risk is Risk.DESTRUCTIVE
    assert decision.requires_approval is True


# -- tools/list filtering ----------------------------------------------------------------------

ALL_TOOLS = [
    "notes_db__list_notes",
    "notes_db__get_note",
    "notes_db__search_notes",
    "notes_db__create_note",
    "notes_db__delete_note",
    "notes_db__run_sql",
    "files__list_files",
    "files__read_file",
    "files__write_file",
    "files__delete_file",
    "evil__get_weather",
]


def test_reader_sees_only_read_tools(engine: PolicyEngine) -> None:
    visible = engine.visible_tools(who("reader"), ALL_TOOLS)
    assert set(visible) == {
        "notes_db__list_notes",
        "notes_db__get_note",
        "notes_db__search_notes",
        "files__list_files",
        "files__read_file",
    }
    assert "files__delete_file" not in visible, "a reader must not even see the delete tool"
    assert "notes_db__run_sql" not in visible, "an explicitly denied tool is hidden too"


def test_editor_sees_write_and_delete(engine: PolicyEngine) -> None:
    visible = set(engine.visible_tools(who("editor"), ALL_TOOLS))
    assert "files__delete_file" in visible
    assert "notes_db__run_sql" in visible
    assert "evil__get_weather" not in visible


def test_admin_sees_both_real_upstreams_but_not_evil(engine: PolicyEngine) -> None:
    visible = set(engine.visible_tools(who("admin"), ALL_TOOLS))
    assert visible == set(ALL_TOOLS) - {"evil__get_weather"}


def test_listing_ignores_argument_constraints(engine: PolicyEngine) -> None:
    """A tool is listed if it could be called with *some* arguments."""
    assert "files__write_file" in engine.visible_tools(who("editor"), ["files__write_file"])


def test_no_principal_sees_nothing(engine: PolicyEngine) -> None:
    assert engine.visible_tools(None, ALL_TOOLS) == []


def test_a_deny_in_one_role_hides_the_tool_despite_an_allow_in_another(
    engine: PolicyEngine,
) -> None:
    visible = engine.visible_tools(who("reader", "admin"), ["notes_db__run_sql"])
    assert visible == []


# -- property tests ----------------------------------------------------------------------------


@given(
    server=st.text(alphabet="abcdefghij_", min_size=1, max_size=10),
    tool=st.text(alphabet="abcdefghij_", min_size=1, max_size=10),
    args=st.dictionaries(
        st.sampled_from(["path", "query", "note_id", "title", "body", "content", "limit"]),
        st.one_of(st.text(max_size=30), st.integers(-100, 100), st.booleans(), st.none()),
        max_size=5,
    ),
)
@hypothesis_settings(max_examples=300, deadline=None)
def test_an_allow_always_names_the_rule_that_granted_it(
    server: str, tool: str, args: dict[str, Any]
) -> None:
    """Deny by default, as a property: nothing is allowed without a rule that says so."""
    engine = make_engine()
    name = f"{server}__{tool}"
    decision = engine.evaluate(who("reader"), name, args)
    if decision.allowed:
        assert decision.rule_id is not None
        assert name in engine.visible_tools(who("reader"), [name])
    else:
        assert name not in engine.visible_tools(who("reader"), [name]) or decision.failures


@given(
    tool=st.text(alphabet="abcdefghij_", min_size=1, max_size=12),
    args=st.dictionaries(
        st.sampled_from(["path", "content"]),
        st.text(max_size=40),
        max_size=2,
    ),
)
@hypothesis_settings(max_examples=200, deadline=None)
def test_a_reader_is_never_granted_a_write_or_delete_tool(tool: str, args: dict[str, Any]) -> None:
    engine = make_engine()
    for server in ("files", "notes_db"):
        decision = engine.evaluate(who("reader"), f"{server}__{tool}", args)
        if decision.allowed:
            assert engine.risk_for(f"{server}__{tool}") is Risk.READ


@given(roles=st.lists(st.text(alphabet="abcxyz", min_size=1, max_size=6), max_size=3))
@hypothesis_settings(max_examples=100, deadline=None)
def test_unknown_roles_never_grant_the_destructive_tool(roles: list[str]) -> None:
    engine = make_engine()
    known = {"reader", "editor", "admin", "redteam"}
    if set(roles) & known:
        return
    decision = engine.evaluate(who(*roles), "files__delete_file", {"path": "a.md"})
    assert decision.denied


@given(
    path=st.text(alphabet="./abcxyz", min_size=1, max_size=24),
)
@hypothesis_settings(max_examples=400, deadline=None)
def test_no_path_an_editor_can_write_ever_escapes_the_root(path: str) -> None:
    """The gateway-side half of sandbox enforcement, as a property."""
    import posixpath

    engine = make_engine()
    decision = engine.evaluate(who("editor"), "files__write_file", {"path": path, "content": "x"})
    if decision.allowed:
        normalised = posixpath.normpath(path)
        assert not normalised.startswith("..")
        assert not normalised.startswith("/")


# -- config-level guards -----------------------------------------------------------------------


def test_a_deny_rule_with_constraints_is_rejected_at_load(tmp_path: Path) -> None:
    """A conditional deny would turn its own condition into the bypass."""
    path = tmp_path / "policies.yaml"
    path.write_text(
        "roles:\n  reader:\n    rules:\n"
        "      - id: bad-deny\n        effect: deny\n        tools: ['files__*']\n"
        "        constraints: {path: {starts_with: '/etc'}}\n"
    )
    with pytest.raises(ConfigError, match="deny rule must not have constraints"):
        load_policies_config(path)


@pytest.mark.parametrize("pattern", ["*", "files", "read_file", "__read", "files__"])
def test_a_pattern_that_does_not_name_a_server_is_rejected(tmp_path: Path, pattern: str) -> None:
    path = tmp_path / "policies.yaml"
    path.write_text(
        f"roles:\n  reader:\n    rules:\n      - {{id: r, effect: allow, tools: ['{pattern}']}}\n"
    )
    with pytest.raises(ConfigError, match="must name a server and a tool"):
        load_policies_config(path)


def test_a_server_name_may_not_contain_the_separator(tmp_path: Path) -> None:
    from warden.config import load_servers_config

    path = tmp_path / "servers.yaml"
    path.write_text(
        "upstreams:\n  - name: a__b\n    transport: {kind: http, url: 'http://x/mcp'}\n"
    )
    with pytest.raises(ConfigError, match="must not contain"):
        load_servers_config(path)


def test_an_empty_policy_file_denies_everything(
    tmp_path: Path, servers_config: ServersConfig
) -> None:
    path = tmp_path / "policies.yaml"
    path.write_text("roles: {}\n")
    engine = PolicyEngine(load_policies_config(path), servers_config)
    decision = engine.evaluate(who("admin"), "files__read_file", {"path": "a.md"})
    assert decision.denied
    assert engine.visible_tools(who("admin"), ALL_TOOLS) == []


def test_describe_summarises_the_policy(engine: PolicyEngine) -> None:
    summary = engine.describe()
    assert "reader" in summary["roles"]
    assert any(rule["effect"] == "deny" for rule in summary["roles"]["reader"])
    assert summary["tool_risk"]["files__delete_file"] == "destructive"


# -- hot reload --------------------------------------------------------------------------------


def write_policy(path: Path, tools: list[str], rule_id: str = "r1") -> None:
    rendered = ", ".join(f"'{tool}'" for tool in tools)
    path.write_text(
        f"roles:\n  reader:\n    rules:\n      - {{id: {rule_id}, effect: allow, tools: [{rendered}]}}\n"
    )


def test_reload_picks_up_a_change(tmp_path: Path, servers_config: ServersConfig) -> None:
    path = tmp_path / "policies.yaml"
    write_policy(path, ["files__read_file"])
    store = PolicyStore(path, servers_config)
    assert store.engine.evaluate(who("reader"), "files__read_file", {}).allowed
    assert store.engine.evaluate(who("reader"), "files__write_file", {}).denied

    write_policy(path, ["files__read_file", "files__write_file"], rule_id="r2")
    changed, message = store.reload()
    assert changed and message == "reloaded"
    assert store.engine.evaluate(who("reader"), "files__write_file", {}).allowed
    assert store.reload_count == 1


def test_reload_with_no_change_reports_so(tmp_path: Path, servers_config: ServersConfig) -> None:
    path = tmp_path / "policies.yaml"
    write_policy(path, ["files__read_file"])
    store = PolicyStore(path, servers_config)
    changed, message = store.reload()
    assert not changed and message == "no change"
    assert store.reload_count == 0


def test_a_broken_file_keeps_the_old_policy_in_force(
    tmp_path: Path, servers_config: ServersConfig
) -> None:
    """The important case: a bad edit must neither open the gateway up nor shut it down."""
    path = tmp_path / "policies.yaml"
    write_policy(path, ["files__read_file"])
    store = PolicyStore(path, servers_config)

    path.write_text(
        "roles:\n  reader:\n    rules: [{id: r1, effect: maybe, tools: ['files__*']}]\n"
    )
    changed, message = store.reload()
    assert not changed
    assert message.startswith("rejected")
    assert store.last_error is not None

    assert store.engine.evaluate(who("reader"), "files__read_file", {}).allowed
    assert store.engine.evaluate(who("reader"), "files__delete_file", {}).denied


def test_a_deleted_file_keeps_the_old_policy_in_force(
    tmp_path: Path, servers_config: ServersConfig
) -> None:
    path = tmp_path / "policies.yaml"
    write_policy(path, ["files__read_file"])
    store = PolicyStore(path, servers_config)
    path.unlink()
    changed, _ = store.reload()
    assert not changed
    assert store.engine.evaluate(who("reader"), "files__read_file", {}).allowed


def test_a_missing_file_at_startup_is_a_hard_error(
    tmp_path: Path, servers_config: ServersConfig
) -> None:
    """At startup there is no previous policy to fall back to, so refuse to start."""
    with pytest.raises(ConfigError):
        PolicyStore(tmp_path / "nope.yaml", servers_config)


def test_status_reports_what_is_loaded(tmp_path: Path, servers_config: ServersConfig) -> None:
    path = tmp_path / "policies.yaml"
    write_policy(path, ["files__read_file"])
    store = PolicyStore(path, servers_config)
    status = store.status()
    assert status["roles"] == ["reader"]
    assert status["rule_count"] == 1
    assert status["reload_count"] == 0
    assert status["last_error"] is None
