"""Config loading: the shipped files are valid, and bad files fail loudly."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from warden.config import (
    GatewayConfig,
    OutputAction,
    PoliciesConfig,
    Risk,
    ServersConfig,
    StdioTransport,
    check_regex_safety,
    load_gateway_config,
    load_policies_config,
    load_servers_config,
    load_yaml_model,
    namespaced,
    split_namespaced,
)
from warden.errors import ConfigError

pytestmark = pytest.mark.unit


def test_example_configs_load(repo_root: Path) -> None:
    gateway = load_gateway_config(repo_root / "config" / "gateway.example.yaml")
    servers = load_servers_config(repo_root / "config" / "servers.example.yaml")
    policies = load_policies_config(repo_root / "config" / "policies.example.yaml")
    assert gateway.limits.max_result_bytes == 262144
    assert {u.name for u in servers.upstreams} == {"notes_db", "files", "evil"}
    assert "reader" in policies.roles


def test_shipped_servers_config_marks_evil_disabled_and_untrusted(
    servers_config: ServersConfig,
) -> None:
    evil = servers_config.by_name("evil")
    assert evil is not None
    assert evil.enabled is False, "the malicious server must never be on by default"
    assert evil.trusted is False
    assert evil.effective_output_action is OutputAction.BLOCK
    assert [u.name for u in servers_config.enabled] == ["notes_db", "files"]


def test_trusted_server_wraps_flagged_output(servers_config: ServersConfig) -> None:
    notes = servers_config.by_name("notes_db")
    assert notes is not None and notes.trusted
    assert notes.effective_output_action is OutputAction.WRAP


def test_per_tool_risk_override(servers_config: ServersConfig) -> None:
    files = servers_config.by_name("files")
    assert files is not None
    assert files.risk_for("read_file") is Risk.READ
    assert files.risk_for("delete_file") is Risk.DESTRUCTIVE


def test_missing_file_names_the_file(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yaml"
    with pytest.raises(ConfigError) as info:
        load_gateway_config(missing)
    assert str(missing) in str(info.value)
    assert "does not exist" in str(info.value)


def test_wrong_type_names_the_key(tmp_path: Path) -> None:
    path = tmp_path / "gateway.yaml"
    path.write_text("limits:\n  max_result_bytes: not-a-number\n")
    with pytest.raises(ConfigError) as info:
        load_gateway_config(path)
    assert info.value.key == "limits.max_result_bytes"
    assert "gateway.yaml" in str(info.value)


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "gateway.yaml"
    path.write_text("limits:\n  max_reslut_bytes: 1024\n")
    with pytest.raises(ConfigError) as info:
        load_gateway_config(path)
    assert "max_reslut_bytes" in str(info.value)


def test_malformed_yaml_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "gateway.yaml"
    path.write_text("limits: [unclosed\n")
    with pytest.raises(ConfigError) as info:
        load_gateway_config(path)
    assert "not valid YAML" in str(info.value)


def test_non_mapping_top_level_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "gateway.yaml"
    path.write_text("- one\n- two\n")
    with pytest.raises(ConfigError) as info:
        load_gateway_config(path)
    assert "top level must be a mapping" in str(info.value)


def test_empty_file_uses_defaults(tmp_path: Path) -> None:
    path = tmp_path / "gateway.yaml"
    path.write_text("")
    assert load_gateway_config(path).limits.max_result_bytes == 262144


@pytest.mark.parametrize("name", ["Notes", "1notes", "n", "notes-db", "a" * 40, ""])
def test_invalid_upstream_names_rejected(tmp_path: Path, name: str) -> None:
    path = tmp_path / "servers.yaml"
    path.write_text(
        f"upstreams:\n  - name: {name!r}\n    transport: {{kind: http, url: 'http://x/mcp'}}\n"
    )
    with pytest.raises(ConfigError):
        load_servers_config(path)


def test_duplicate_upstream_name_rejected(tmp_path: Path) -> None:
    path = tmp_path / "servers.yaml"
    path.write_text(
        "upstreams:\n"
        "  - name: notes\n    transport: {kind: http, url: 'http://x/mcp'}\n"
        "  - name: notes\n    transport: {kind: http, url: 'http://y/mcp'}\n"
    )
    with pytest.raises(ConfigError) as info:
        load_servers_config(path)
    assert "duplicate upstream name" in str(info.value)


def test_non_http_upstream_url_rejected(tmp_path: Path) -> None:
    path = tmp_path / "servers.yaml"
    path.write_text(
        "upstreams:\n  - name: notes\n    transport: {kind: http, url: 'ftp://x/mcp'}\n"
    )
    with pytest.raises(ConfigError) as info:
        load_servers_config(path)
    assert info.value.key == "upstreams.0.transport.http.url"


def test_env_reference_is_expanded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_TEST_UPSTREAM_TOKEN", "value-from-env")
    path = tmp_path / "servers.yaml"
    path.write_text(
        "upstreams:\n"
        "  - name: notes\n"
        "    transport:\n"
        "      kind: stdio\n"
        "      command: python\n"
        "      env: {UPSTREAM_TOKEN: '${WARDEN_TEST_UPSTREAM_TOKEN}'}\n"
    )
    config = load_servers_config(path)
    transport = config.upstreams[0].transport
    assert isinstance(transport, StdioTransport)
    assert transport.env == {"UPSTREAM_TOKEN": "value-from-env"}


def test_unset_env_reference_fails_loudly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WARDEN_TEST_ABSENT", raising=False)
    path = tmp_path / "servers.yaml"
    path.write_text(
        "upstreams:\n"
        "  - name: notes\n"
        "    transport:\n"
        "      kind: stdio\n"
        "      command: python\n"
        "      env: {UPSTREAM_TOKEN: '${WARDEN_TEST_ABSENT}'}\n"
    )
    with pytest.raises(ConfigError) as info:
        load_servers_config(path)
    assert "WARDEN_TEST_ABSENT" in str(info.value)


def test_duplicate_rule_id_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policies.yaml"
    path.write_text(
        "roles:\n"
        "  reader:\n    rules:\n      - {id: dup, effect: allow, tools: ['a__b']}\n"
        "  editor:\n    rules:\n      - {id: dup, effect: allow, tools: ['a__c']}\n"
    )
    with pytest.raises(ConfigError) as info:
        load_policies_config(path)
    assert "duplicate rule id" in str(info.value)


def test_empty_constraint_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policies.yaml"
    path.write_text(
        "roles:\n  reader:\n    rules:\n"
        "      - {id: r, effect: allow, tools: ['a__b'], constraints: {path: {}}}\n"
    )
    with pytest.raises(ConfigError) as info:
        load_policies_config(path)
    assert "at least one condition" in str(info.value)


@pytest.mark.parametrize(
    "pattern",
    ["(a+)+", "(a*)*", "(\\w+\\s?)+", "x" * 250],
)
def test_catastrophic_or_oversized_regex_rejected(pattern: str) -> None:
    with pytest.raises(ValueError):
        check_regex_safety(pattern)


@pytest.mark.parametrize("pattern", ["[A-Za-z0-9._/-]{1,256}", "^notes/[a-z]+\\.md$", "\\d{4}"])
def test_reasonable_regex_accepted(pattern: str) -> None:
    check_regex_safety(pattern)


def test_regex_in_policy_file_is_checked_at_load(tmp_path: Path) -> None:
    path = tmp_path / "policies.yaml"
    path.write_text(
        "roles:\n  reader:\n    rules:\n"
        "      - {id: r, effect: allow, tools: ['a__b'], constraints: {p: {regex: '(a+)+'}}}\n"
    )
    with pytest.raises(ConfigError) as info:
        load_policies_config(path)
    assert "quantifier" in str(info.value)


@pytest.mark.parametrize("pattern", ["notes db", "tool;name", "a/b"])
def test_invalid_tool_glob_rejected(tmp_path: Path, pattern: str) -> None:
    path = tmp_path / "policies.yaml"
    path.write_text(
        f"roles:\n  reader:\n    rules:\n      - {{id: r, effect: allow, tools: ['{pattern}']}}\n"
    )
    with pytest.raises(ConfigError):
        load_policies_config(path)


def test_namespacing_round_trip() -> None:
    assert namespaced("files", "read_file") == "files__read_file"
    assert split_namespaced("files__read_file") == ("files", "read_file")
    assert split_namespaced("files_read_file") is None
    assert split_namespaced("__read") is None
    assert split_namespaced("files__") is None


def test_limits_lookup_prefers_the_most_generous_role(gateway_config: GatewayConfig) -> None:
    limits = gateway_config.limits
    assert limits.for_roles(("reader",)).daily_destructive_calls == 0
    assert limits.for_roles(("reader", "editor")).per_principal.capacity == 120
    assert limits.for_roles(("nobody",)) == limits.default


def test_models_are_frozen(gateway_config: GatewayConfig) -> None:
    with pytest.raises(ValidationError):
        gateway_config.limits.max_result_bytes = 1  # type: ignore[misc]


def test_load_yaml_model_accepts_any_strict_model(tmp_path: Path) -> None:
    path = tmp_path / "policies.yaml"
    path.write_text("roles: {}\n")
    assert load_yaml_model(path, PoliciesConfig).roles == {}
    assert isinstance(load_yaml_model(tmp_path / "policies.yaml", PoliciesConfig), PoliciesConfig)


def test_servers_config_rejects_unknown_transport_kind(tmp_path: Path) -> None:
    path = tmp_path / "servers.yaml"
    path.write_text("upstreams:\n  - name: notes\n    transport: {kind: carrier_pigeon}\n")
    with pytest.raises(ConfigError):
        load_servers_config(path)


def test_gateway_config_defaults_are_fail_closed() -> None:
    config = GatewayConfig()
    assert config.limits.fail_open_when_limiter_down is False
    assert config.scan.classifier_enabled is False
    assert config.approval.allow_self_approval is False


def test_a_body_limit_smaller_than_the_argument_limit_is_refused() -> None:
    """Otherwise a call with permitted arguments could never arrive, which would look like a bug."""
    from warden.config import LimitsConfig

    with pytest.raises(ValueError, match="max_request_body_bytes"):
        LimitsConfig(max_argument_bytes=65536, max_request_body_bytes=4096)


def test_the_shipped_body_limit_leaves_room_for_the_largest_arguments() -> None:
    from warden.config import load_gateway_config

    limits = load_gateway_config(
        Path(__file__).resolve().parents[2] / "config" / "gateway.yaml"
    ).limits
    assert limits.max_request_body_bytes >= 2 * limits.max_argument_bytes


def test_the_shipped_config_pins_the_classifier_to_a_commit() -> None:
    import re

    from warden.config import load_gateway_config

    scan = load_gateway_config(Path(__file__).resolve().parents[2] / "config" / "gateway.yaml").scan
    assert re.fullmatch(r"[0-9a-f]{40}", scan.classifier_revision)


def test_metrics_networks_parse_and_default_to_none() -> None:
    from warden.config import Settings

    assert Settings(metrics_allow_networks="").metrics_networks() == []
    parsed = Settings(metrics_allow_networks="172.28.0.0/24, fd00::/64").metrics_networks()
    assert [str(n) for n in parsed] == ["172.28.0.0/24", "fd00::/64"]


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0"])
def test_a_metrics_network_that_allows_everyone_is_refused(value: str) -> None:
    from warden.config import Settings
    from warden.errors import ConfigError

    with pytest.raises(ConfigError, match="every address"):
        Settings(metrics_allow_networks=value).metrics_networks()


@pytest.mark.parametrize("value", ["prometheus", "172.28.0.1/24", "10.0.0.0/33"])
def test_a_malformed_metrics_network_is_a_config_error_not_ignored(value: str) -> None:
    """`172.28.0.1/24` has host bits set: probably a typo for the subnet, so say so."""
    from warden.config import Settings
    from warden.errors import ConfigError

    with pytest.raises(ConfigError, match="METRICS_ALLOW_NETWORKS"):
        Settings(metrics_allow_networks=value).metrics_networks()


def _stdio_servers(tmp_path: Path, env_value: str) -> Path:
    path = tmp_path / "servers.yaml"
    path.write_text(
        "upstreams:\n"
        "  - name: notes\n"
        "    transport:\n"
        "      kind: stdio\n"
        "      command: python\n"
        f"      env: {{NOTES_DB_PATH: '{env_value}'}}\n"
    )
    return path


def test_a_default_is_used_when_the_variable_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WARDEN_TEST_DB", raising=False)
    config = load_servers_config(_stdio_servers(tmp_path, "${WARDEN_TEST_DB:-./data/n.sqlite3}"))
    transport = config.upstreams[0].transport
    assert isinstance(transport, StdioTransport)
    assert transport.env == {"NOTES_DB_PATH": "./data/n.sqlite3"}


def test_a_set_variable_beats_its_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_TEST_DB", "/var/lib/warden/data/n.sqlite3")
    config = load_servers_config(_stdio_servers(tmp_path, "${WARDEN_TEST_DB:-./data/n.sqlite3}"))
    transport = config.upstreams[0].transport
    assert isinstance(transport, StdioTransport)
    assert transport.env["NOTES_DB_PATH"] == "/var/lib/warden/data/n.sqlite3"


def test_the_strict_form_still_fails_loudly_next_to_a_defaulted_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A default is opt-in per reference; it must not relax its neighbours."""
    monkeypatch.delenv("WARDEN_TEST_DB", raising=False)
    monkeypatch.delenv("WARDEN_TEST_SECRET", raising=False)
    path = _stdio_servers(tmp_path, "${WARDEN_TEST_DB:-x}${WARDEN_TEST_SECRET}")
    with pytest.raises(ConfigError, match="WARDEN_TEST_SECRET"):
        load_servers_config(path)


def test_an_empty_default_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WARDEN_TEST_DB", raising=False)
    config = load_servers_config(_stdio_servers(tmp_path, "${WARDEN_TEST_DB:-}"))
    transport = config.upstreams[0].transport
    assert isinstance(transport, StdioTransport)
    assert transport.env["NOTES_DB_PATH"] == ""


def test_the_shipped_servers_config_loads_without_any_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`make run` on a fresh clone exports nothing; the shipped file must still load."""
    for name in ("NOTES_DB_PATH", "FILES_SANDBOX_ROOT"):
        monkeypatch.delenv(name, raising=False)
    root = Path(__file__).resolve().parents[2]
    config = load_servers_config(root / "config" / "servers.yaml")
    by_name = {u.name: u.transport for u in config.upstreams}
    assert by_name["notes_db"].env["NOTES_DB_PATH"] == "./data/notes.sqlite3"  # type: ignore[union-attr]
    assert by_name["files"].env["FILES_SANDBOX_ROOT"] == "./sandbox"  # type: ignore[union-attr]
