"""Settings from the environment and validated YAML config files.

Three files make up the gateway's policy surface:

* `config/gateway.yaml`   — limits, timeouts and scanner switches
* `config/servers.yaml`   — the upstream MCP servers and how much we trust each
* `config/policies.yaml`  — which role may call which tool with which arguments

All three are strict: an unknown key is an error, not a silent default, because a typo in a
security file must never quietly widen access.
"""

from __future__ import annotations

import os
import re
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Annotated, Any, Final, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from warden.errors import ConfigError

SERVER_NAME_RE: Final = re.compile(r"^[a-z][a-z0-9_]{1,30}$")
TOOL_NAME_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
#: Separator between the upstream server name and the upstream's own tool name.
NAMESPACE_SEP: Final = "__"


class Risk(StrEnum):
    """How much damage a tool can do. Drives approval requirements and budgets."""

    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class OutputAction(StrEnum):
    """What to do with a tool result that the output scanner flagged."""

    BLOCK = "block"
    WRAP = "wrap"


class StrictModel(BaseModel):
    """Base for every config model: unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class StdioTransport(StrictModel):
    """Run the upstream as a child process and speak MCP over its stdin/stdout."""

    kind: Literal["stdio"] = "stdio"
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None


class HttpTransport(StrictModel):
    """Connect to an upstream that serves Streamable HTTP."""

    kind: Literal["http"] = "http"
    url: str

    @field_validator("url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("must start with http:// or https://")
        return value


Transport = Annotated[StdioTransport | HttpTransport, Field(discriminator="kind")]


class ToolOverride(StrictModel):
    """Per-tool overrides for an upstream's defaults."""

    risk: Risk | None = None
    trusted: bool | None = None


class UpstreamConfig(StrictModel):
    """One upstream MCP server."""

    name: str
    transport: Transport
    enabled: bool = True
    timeout_seconds: float = Field(default=20.0, gt=0, le=300)
    default_risk: Risk = Risk.READ
    #: A trusted upstream's clean tools are pinned automatically and flagged output is wrapped
    #: rather than blocked. An untrusted upstream starts quarantined and has output blocked.
    trusted: bool = False
    #: What to do when the output scanner flags a result. Defaults by `trusted`.
    output_action: OutputAction | None = None
    max_concurrency: int = Field(default=8, ge=1, le=256)
    tools: dict[str, ToolOverride] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _valid_name(cls, value: str) -> str:
        if not SERVER_NAME_RE.match(value):
            raise ValueError(f"must match {SERVER_NAME_RE.pattern}")
        if NAMESPACE_SEP in value:
            raise ValueError(
                f"must not contain '{NAMESPACE_SEP}', which separates the server from the tool"
            )
        return value

    @property
    def effective_output_action(self) -> OutputAction:
        """Block flagged output from untrusted servers; wrap it for trusted ones."""
        if self.output_action is not None:
            return self.output_action
        return OutputAction.WRAP if self.trusted else OutputAction.BLOCK

    def risk_for(self, tool: str) -> Risk:
        """Risk level for one of this upstream's tools."""
        override = self.tools.get(tool)
        if override is not None and override.risk is not None:
            return override.risk
        return self.default_risk


class ServersConfig(StrictModel):
    """The whole of `config/servers.yaml`."""

    upstreams: list[UpstreamConfig]

    @model_validator(mode="after")
    def _unique_names(self) -> Self:
        seen: set[str] = set()
        for upstream in self.upstreams:
            if upstream.name in seen:
                raise ValueError(f"duplicate upstream name '{upstream.name}'")
            seen.add(upstream.name)
        return self

    @property
    def enabled(self) -> list[UpstreamConfig]:
        return [u for u in self.upstreams if u.enabled]

    def by_name(self, name: str) -> UpstreamConfig | None:
        return next((u for u in self.upstreams if u.name == name), None)


class BucketConfig(StrictModel):
    """A token bucket: `capacity` tokens, refilled at `refill_per_second`."""

    capacity: int = Field(ge=1, le=100_000)
    refill_per_second: float = Field(gt=0, le=10_000)


class RoleLimits(StrictModel):
    """Rate limits and daily budgets for one role."""

    per_principal: BucketConfig = BucketConfig(capacity=60, refill_per_second=1.0)
    per_tool: BucketConfig = BucketConfig(capacity=30, refill_per_second=0.5)
    daily_calls: int = Field(default=2000, ge=1)
    daily_destructive_calls: int = Field(default=25, ge=0)


class LimitsConfig(StrictModel):
    """`limits:` in gateway.yaml."""

    default: RoleLimits = RoleLimits()
    roles: dict[str, RoleLimits] = Field(default_factory=dict)
    max_result_bytes: int = Field(default=256 * 1024, ge=1024)
    max_argument_bytes: int = Field(default=64 * 1024, ge=256)
    #: The whole HTTP request body, refused with 413 before anything parses it. Must leave room
    #: for the largest permitted arguments plus the JSON-RPC envelope around them.
    max_request_body_bytes: int = Field(default=1024 * 1024, ge=1024)
    #: Fail-open is for local development only and logs a warning on every use.
    fail_open_when_limiter_down: bool = False

    @model_validator(mode="after")
    def _body_fits_arguments(self) -> Self:
        if self.max_request_body_bytes < self.max_argument_bytes:
            raise ValueError(
                f"max_request_body_bytes ({self.max_request_body_bytes}) is smaller than "
                f"max_argument_bytes ({self.max_argument_bytes}), so a call with permitted "
                "arguments could never arrive"
            )
        return self

    def for_roles(self, roles: tuple[str, ...]) -> RoleLimits:
        """The most generous limits among the principal's roles, else the default."""
        candidates = [self.roles[r] for r in roles if r in self.roles]
        if not candidates:
            return self.default
        return max(candidates, key=lambda limits: limits.per_principal.capacity)


class ScanConfig(StrictModel):
    """`scan:` in gateway.yaml."""

    classifier_enabled: bool = False
    classifier_model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    #: A full 40-character commit hash, never a branch or tag name: those are mutable. The
    #: default is the commit every published measurement was made with.
    classifier_revision: str = Field(
        default="90c9989b1a342275dd0d1a95aad283c04e075671", pattern=r"^[0-9a-f]{40}$"
    )
    #: 0.999, not the 0.8 this started at. Measured on tests/data (46 attacks, 46 benign):
    #: at 0.8 the model flagged 17.4% of ordinary text, scoring "Never store credentials in the
    #: repository; use the secret store." at 1.0000 - the same as a real injection. No
    #: threshold separates the two classes on that set; 0.999 is the point where it still adds
    #: ~70% independent detection at ~4% false positives. See docs/decisions.md.
    classifier_threshold: float = Field(default=0.999, ge=0.0, le=1.0)
    classifier_timeout_seconds: float = Field(default=2.0, gt=0, le=60)
    classifier_device: Literal["auto", "cpu", "mps"] = "auto"
    #: Score at or above which a tool definition is quarantined instead of merely flagged.
    definition_malicious_score: int = Field(default=5, ge=1)
    definition_suspicious_score: int = Field(default=2, ge=1)
    #: Strings that must never leave in a tool argument. Used by tests and the red-team suite.
    canaries: list[str] = Field(default_factory=list)
    max_definition_description_chars: int = Field(default=1024, ge=64)


class ApprovalConfig(StrictModel):
    """`approval:` in gateway.yaml."""

    wait_seconds: float = Field(default=60.0, gt=0, le=600)
    expiry_seconds: float = Field(default=300.0, gt=0, le=86_400)
    #: Development only: let a principal approve their own request.
    allow_self_approval: bool = False


class GatewayConfig(StrictModel):
    """The whole of `config/gateway.yaml`."""

    limits: LimitsConfig = LimitsConfig()
    scan: ScanConfig = ScanConfig()
    approval: ApprovalConfig = ApprovalConfig()
    upstream_connect_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    tools_refresh_seconds: float = Field(default=300.0, gt=0)
    #: How often each connected upstream is pinged. A failed ping marks it down, so its
    #: tools stop being advertised rather than being handed out and then failing.
    upstream_health_interval_seconds: float = Field(default=5.0, gt=0, le=600)


class Settings(BaseSettings):
    """Process settings, from the environment and `.env`."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True
    )

    database_url: str = "sqlite+aiosqlite:///./data/warden.sqlite3"
    redis_url: str = "redis://localhost:6379/0"

    warden_host: str = "127.0.0.1"
    warden_port: int = 8080
    warden_resource_url: str = "http://localhost:8080/mcp"

    log_level: str = "INFO"
    config_dir: Path = Path("./config")

    jwt_issuer: str = "http://localhost:8080"
    jwt_audience: str = "http://localhost:8080/mcp"
    jwt_key_dir: Path = Path("./keys")
    jwt_default_ttl_seconds: int = 900
    jwt_clock_skew_seconds: int = 30

    otel_enabled: bool = False
    otel_exporter_otlp_endpoint: str = "http://localhost:4318"
    otel_service_name: str = "mcp-warden"

    classifier_enabled: bool = False
    classifier_model: str = "protectai/deberta-v3-base-prompt-injection-v2"

    metrics_enabled: bool = True
    #: Allow an unauthenticated scrape from loopback, which is how a sidecar Prometheus
    #: reaches /metrics. Any other client needs the admin role.
    metrics_allow_localhost: bool = True
    #: Further networks allowed to scrape /metrics without a credential, as comma-separated
    #: CIDRs. Empty by default. Set by docker-compose to its own private bridge subnet, which
    #: is how a Prometheus *container* reaches a gateway container - not over loopback.
    metrics_allow_networks: str = ""

    def metrics_networks(self) -> list[IPv4Network | IPv6Network]:
        """The parsed CIDRs; an unparseable entry is a configuration error, not ignored."""
        networks: list[IPv4Network | IPv6Network] = []
        for raw in self.metrics_allow_networks.split(","):
            entry = raw.strip()
            if not entry:
                continue
            try:
                networks.append(ip_network(entry, strict=True))
            except ValueError as exc:
                raise ConfigError(
                    "environment", "METRICS_ALLOW_NETWORKS", f"'{entry}' is not a CIDR: {exc}"
                ) from exc
            if networks[-1].prefixlen == 0:
                raise ConfigError(
                    "environment",
                    "METRICS_ALLOW_NETWORKS",
                    f"'{entry}' would allow every address; name the scraper's network",
                )
        return networks

    #: Host headers the MCP endpoint accepts, comma separated. DNS-rebinding protection
    #: rejects anything else, which is what stops a web page from driving a local gateway.
    transport_allowed_hosts: str = "127.0.0.1:*,localhost:*,[::1]:*"
    transport_allowed_origins: str = "http://127.0.0.1:*,http://localhost:*,http://[::1]:*"

    @property
    def allowed_hosts(self) -> list[str]:
        return [part.strip() for part in self.transport_allowed_hosts.split(",") if part.strip()]

    @property
    def allowed_origins(self) -> list[str]:
        return [part.strip() for part in self.transport_allowed_origins.split(",") if part.strip()]

    @property
    def gateway_yaml(self) -> Path:
        return self.config_dir / "gateway.yaml"

    @property
    def servers_yaml(self) -> Path:
        return self.config_dir / "servers.yaml"

    @property
    def policies_yaml(self) -> Path:
        return self.config_dir / "policies.yaml"


def _first_error_location(exc: ValidationError) -> tuple[str | None, str]:
    """Turn a pydantic error into (key path, human problem) for the first failure."""
    error = exc.errors()[0]
    location = ".".join(str(part) for part in error["loc"]) or None
    return location, str(error["msg"])


def load_yaml_model[ModelT: BaseModel](path: Path | str, model: type[ModelT]) -> ModelT:
    """Read a YAML file and validate it into `model`, raising `ConfigError` on any problem."""
    file = Path(path)
    try:
        raw_text = file.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(str(file), None, "file does not exist") from exc
    except OSError as exc:
        raise ConfigError(str(file), None, f"could not be read: {exc}") from exc
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(str(file), None, f"is not valid YAML: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(
            str(file), None, f"top level must be a mapping, got {type(data).__name__}"
        )
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        key, problem = _first_error_location(exc)
        raise ConfigError(str(file), key, problem) from exc


def load_servers_config(path: Path | str) -> ServersConfig:
    """Load and validate `servers.yaml`, expanding `${VAR}` references in stdio env values."""
    config = load_yaml_model(path, ServersConfig)
    return _expand_env(config)


def _expand_env(config: ServersConfig) -> ServersConfig:
    """Replace `${VAR}` in stdio env values, args and http urls with the process environment.

    This is how upstream credentials reach an upstream without ever being written to the repo.
    An unset variable is an error, not an empty string, so a missing secret fails loudly.

    `${VAR:-default}` is the one exception, and it is opt-in per reference: it is for settings
    that legitimately differ between a laptop and a container (a data path), never for a
    secret, where a silent default would be exactly the failure the strict form prevents.
    """
    pattern = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")

    def expand(value: str, where: str) -> str:
        def replace(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            resolved = os.environ.get(name)
            if resolved is None and default is not None:
                return default
            if resolved is None:
                raise ConfigError(
                    "servers.yaml",
                    where,
                    f"environment variable '{name}' is referenced but not set",
                )
            return resolved

        return pattern.sub(replace, value)

    upstreams: list[UpstreamConfig] = []
    for upstream in config.upstreams:
        transport = upstream.transport
        if isinstance(transport, StdioTransport):
            new_transport: StdioTransport | HttpTransport = transport.model_copy(
                update={
                    "env": {
                        key: expand(value, f"upstreams.{upstream.name}.transport.env.{key}")
                        for key, value in transport.env.items()
                    },
                    "args": [
                        expand(arg, f"upstreams.{upstream.name}.transport.args")
                        for arg in transport.args
                    ],
                }
            )
        else:
            new_transport = transport.model_copy(
                update={"url": expand(transport.url, f"upstreams.{upstream.name}.transport.url")}
            )
        upstreams.append(upstream.model_copy(update={"transport": new_transport}))
    return config.model_copy(update={"upstreams": upstreams})


def load_gateway_config(path: Path | str) -> GatewayConfig:
    """Load and validate `gateway.yaml`."""
    return load_yaml_model(path, GatewayConfig)


# --------------------------------------------------------------------------------------------
# Policy models (config/policies.yaml)
# --------------------------------------------------------------------------------------------

MAX_REGEX_LENGTH: Final = 200
#: Shapes that can backtrack exponentially. A quantifier applied to a group that itself ends in
#: a quantifier is the classic catastrophic case: (a+)+, (a*)*, (\w+\s?)+ and friends.
_NESTED_QUANTIFIER_RE: Final = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")
_ALTERNATION_QUANTIFIER_RE: Final = re.compile(r"\([^()]*\|[^()]*\)\s*[+*]\s*[+*]")


def check_regex_safety(pattern: str) -> None:
    """Raise ValueError if `pattern` is too long, invalid, or obviously catastrophic.

    This runs at config load time, so a bad pattern is rejected before it can be used as a
    denial-of-service against the gateway. The check is deliberately conservative: it refuses
    some safe patterns rather than admitting an unsafe one.
    """
    if len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError(f"regex longer than {MAX_REGEX_LENGTH} characters")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"not a valid regular expression: {exc}") from exc
    if _NESTED_QUANTIFIER_RE.search(pattern) or _ALTERNATION_QUANTIFIER_RE.search(pattern):
        raise ValueError(
            "nested quantifier can backtrack exponentially; rewrite without a quantified group"
        )


class ArgumentConstraint(StrictModel):
    """Conditions one call argument must satisfy.

    Every field is optional; the ones that are set must all hold. A constraint on an argument
    that is missing, or whose type does not fit the constraint, denies the call: a constraint
    can only ever narrow access, never widen it.
    """

    equals: Any | None = None
    in_list: list[Any] | None = None
    min: float | None = None
    max: float | None = None
    max_length: int | None = Field(default=None, ge=0)
    regex: str | None = None
    #: Compared against the normalised relative path, so "a/../../etc" cannot slip through.
    starts_with: str | None = None
    #: Allow the argument to be absent. Off by default: a named constraint implies a required
    #: argument, which is the safe reading.
    optional: bool = False

    @field_validator("regex")
    @classmethod
    def _safe_regex(cls, value: str | None) -> str | None:
        if value is not None:
            check_regex_safety(value)
        return value

    @model_validator(mode="after")
    def _at_least_one(self) -> Self:
        if all(
            getattr(self, name) is None
            for name in ("equals", "in_list", "min", "max", "max_length", "regex", "starts_with")
        ):
            raise ValueError("a constraint must set at least one condition")
        return self


class PolicyRule(StrictModel):
    """One allow or deny rule inside a role."""

    id: str = Field(min_length=1, max_length=64)
    effect: Literal["allow", "deny"]
    #: Glob patterns over namespaced tool names. `*` never crosses the `__` separator.
    tools: list[str] = Field(min_length=1)
    constraints: dict[str, ArgumentConstraint] = Field(default_factory=dict)
    #: Force or waive human approval for the matched calls, overriding the risk default.
    require_approval: bool | None = None
    #: Treat the matched tools as this risk level instead of the upstream default.
    risk: Risk | None = None
    description: str | None = None

    @field_validator("tools")
    @classmethod
    def _valid_patterns(cls, value: list[str]) -> list[str]:
        for pattern in value:
            if not pattern:
                raise ValueError("tool pattern must not be empty")
            if len(pattern) > 128:
                raise ValueError("tool pattern longer than 128 characters")
            if not re.fullmatch(r"[A-Za-z0-9_*?.\[\]-]+", pattern):
                raise ValueError(
                    f"tool pattern '{pattern}' may only contain name characters and globs"
                )
            # A pattern must name a server. Allowing a bare '*' would let one glob cross the
            # '__' separator and silently grant every tool on every upstream.
            server, separator, tool = pattern.partition(NAMESPACE_SEP)
            if not separator or not server or not tool:
                raise ValueError(
                    f"tool pattern '{pattern}' must name a server and a tool, "
                    f"for example 'files{NAMESPACE_SEP}*' - a glob never crosses "
                    f"'{NAMESPACE_SEP}'"
                )
        return value

    @model_validator(mode="after")
    def _deny_rules_have_no_constraints(self) -> Self:
        """A deny rule applies on the tool name alone.

        If a deny could be conditional on an argument, the condition becomes the bypass: pass an
        argument of the wrong type, the constraint stops matching, the deny stops applying and an
        allow rule further down lets the call through. Rejecting the combination at load time is
        clearer than silently ignoring it.
        """
        if self.effect == "deny" and self.constraints:
            raise ValueError(
                "a deny rule must not have constraints: a deny applies to the tool, not to "
                "particular arguments. Express the narrow case as an allow rule instead."
            )
        return self


class RolePolicy(StrictModel):
    """All rules that apply to one role."""

    rules: list[PolicyRule] = Field(default_factory=list)
    description: str | None = None


class PoliciesConfig(StrictModel):
    """The whole of `config/policies.yaml`."""

    roles: dict[str, RolePolicy] = Field(default_factory=dict)
    #: Risk overrides keyed by namespaced tool name, e.g. `files__delete_file: destructive`.
    tool_risk: dict[str, Risk] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Self:
        seen: set[str] = set()
        for role_name, role in self.roles.items():
            for rule in role.rules:
                if rule.id in seen:
                    raise ValueError(
                        f"duplicate rule id '{rule.id}' (second use in role '{role_name}')"
                    )
                seen.add(rule.id)
        return self


def load_policies_config(path: Path | str) -> PoliciesConfig:
    """Load and validate `policies.yaml`."""
    return load_yaml_model(path, PoliciesConfig)


def namespaced(server: str, tool: str) -> str:
    """The gateway-visible name of an upstream tool."""
    return f"{server}{NAMESPACE_SEP}{tool}"


def split_namespaced(name: str) -> tuple[str, str] | None:
    """Split `server__tool` back into its parts, or None if `name` is not namespaced."""
    server, separator, tool = name.partition(NAMESPACE_SEP)
    if not separator or not server or not tool:
        return None
    return server, tool


__all__ = [
    "NAMESPACE_SEP",
    "ApprovalConfig",
    "ArgumentConstraint",
    "BucketConfig",
    "GatewayConfig",
    "HttpTransport",
    "LimitsConfig",
    "OutputAction",
    "PoliciesConfig",
    "PolicyRule",
    "Risk",
    "RoleLimits",
    "RolePolicy",
    "ScanConfig",
    "ServersConfig",
    "Settings",
    "StdioTransport",
    "ToolOverride",
    "UpstreamConfig",
    "check_regex_safety",
    "load_gateway_config",
    "load_policies_config",
    "load_servers_config",
    "load_yaml_model",
    "namespaced",
    "split_namespaced",
]
