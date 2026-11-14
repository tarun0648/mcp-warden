"""The red-team case format.

A case is data, not code. That matters for three reasons: a case can be added without touching
the runner, the whole suite can be diffed in review, and the report can name the exact case
that regressed. Strict models so a typo in a reason code fails at load time rather than
quietly passing a case that asserts nothing.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from warden.errors import ReasonCode


class Expectation(StrEnum):
    """What a step should produce."""

    #: The call went through and the tool answered.
    ALLOWED = "allowed"
    #: The gateway refused it, with a `WARDEN_DENIED:*` reason code.
    DENIED = "denied"
    #: Waiting for a human: `WARDEN_PENDING:approval`.
    PENDING = "pending"
    #: The upstream itself returned an error result, and the gateway passed it through.
    #: Distinguished from `denied` because "the tool said no" is not "the gateway said no".
    UPSTREAM_ERROR = "upstream_error"
    #: Rejected before MCP: a bad credential, a 401 or 403.
    REFUSED_AT_TRANSPORT = "refused_at_transport"


class CaseKind(StrEnum):
    TOOL_CALL = "tool_call"
    #: Assert which tools a role can see. Hiding a poisoned tool is a control in its own right.
    LISTING = "listing"
    #: A raw HTTP request with a chosen credential, for the auth-forgery cases.
    HTTP = "http"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Step(StrictModel):
    """One MCP call and what it should do."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    expect: Expectation
    #: Required for `denied`: the exact reason code. A case that asserts "denied, somehow"
    #: passes when the gateway refuses for the wrong reason, which is how a suite stops
    #: measuring anything.
    reason: str | None = None
    #: Free text explaining what this step is attacking, shown in the report next to a miss.
    note: str | None = None

    @model_validator(mode="after")
    def _reason_required_for_denials(self) -> Self:
        if self.expect is Expectation.DENIED and not self.reason:
            raise ValueError(
                "a 'denied' step must name the expected reason code, or it would pass on any "
                "refusal at all"
            )
        if self.reason is not None:
            valid = {str(code) for code in ReasonCode}
            if self.reason not in valid:
                raise ValueError(f"'{self.reason}' is not a warden reason code")
        return self


class SetupCall(StrictModel):
    """A call made before the steps, to put the world in the right state.

    Not asserted: if a setup call fails the case errors rather than counting as a miss, because
    a broken fixture is not a security finding.
    """

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    role: str = "editor"


class ListingExpectation(StrictModel):
    """Which tools a role must and must not be able to see."""

    visible: list[str] = Field(default_factory=list)
    hidden: list[str] = Field(default_factory=list)


class HttpProbe(StrictModel):
    """A raw request to the MCP endpoint with a chosen credential."""

    #: A named credential the runner knows how to mint: see `redteam.credentials`.
    credential: str
    expect_status: int = 401


class Case(StrictModel):
    """One red-team or benign case."""

    id: str = Field(min_length=3, max_length=64)
    category: str = Field(min_length=3, max_length=40)
    description: str = Field(min_length=10)
    #: True for an attack that must be blocked, False for traffic that must be allowed.
    attack: bool
    kind: CaseKind = CaseKind.TOOL_CALL
    role: str = "redteam"
    #: Gateway config overrides. Cases sharing the same overrides share one gateway process,
    #: so a suite of 90 cases does not start 90 gateways.
    gateway: dict[str, Any] = Field(default_factory=dict)
    #: Which injection payload the evil server should return: plain, base64, json, unicode,
    #: multilingual. Its own field rather than smuggled through `gateway`, because it is an
    #: upstream *server* setting and GatewayConfig would reject it.
    evil_variant: Literal["plain", "base64", "json", "unicode", "multilingual"] = "plain"
    #: Tools to approve through the admin API first, for cases testing something *other* than
    #: quarantine on an untrusted server's tool.
    pre_approve: list[str] = Field(default_factory=list)
    #: Force this many `tools/list` round trips before the steps, to drive the rug pull.
    refresh_listings: int = 0
    setup: list[SetupCall] = Field(default_factory=list)
    steps: list[Step] = Field(default_factory=list)
    listing: ListingExpectation | None = None
    http: HttpProbe | None = None

    @model_validator(mode="after")
    def _shape_matches_kind(self) -> Self:
        if self.kind is CaseKind.TOOL_CALL and not self.steps:
            raise ValueError("a tool_call case needs at least one step")
        if self.kind is CaseKind.LISTING and self.listing is None:
            raise ValueError("a listing case needs a 'listing' block")
        if self.kind is CaseKind.HTTP and self.http is None:
            raise ValueError("an http case needs an 'http' block")
        return self

    @property
    def profile_key(self) -> str:
        """Cases with the same key can share a gateway.

        The evil server's payload variant is part of the key because it is baked into the
        subprocess's environment at startup.
        """
        return yaml.safe_dump(
            {"gateway": self.gateway, "evil_variant": self.evil_variant},
            sort_keys=True,
            default_flow_style=True,
        )


class CaseFile(StrictModel):
    cases: list[Case]


def load_cases(directory: Path | str) -> list[Case]:
    """Load every `*.yaml` under `directory`, rejecting duplicate ids."""
    folder = Path(directory)
    cases: list[Case] = []
    seen: dict[str, str] = {}
    for path in sorted(folder.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        try:
            parsed = CaseFile.model_validate(raw)
        except Exception as exc:
            raise ValueError(f"{path.name}: {exc}") from exc
        for case in parsed.cases:
            if case.id in seen:
                raise ValueError(
                    f"duplicate case id '{case.id}' in {path.name} and {seen[case.id]}"
                )
            seen[case.id] = path.name
            cases.append(case)
    return cases


Outcome = Literal["blocked", "missed", "allowed", "false_positive", "error"]


class CaseResult(StrictModel):
    """What happened when one case ran."""

    case_id: str
    category: str
    attack: bool
    outcome: Outcome
    detail: str = ""
    #: What the gateway actually did, for the "every miss with its evidence" requirement.
    evidence: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def passed(self) -> bool:
        """An attack passes by being blocked; benign traffic passes by being allowed."""
        return self.outcome in ("blocked", "allowed")


__all__ = [
    "Case",
    "CaseFile",
    "CaseKind",
    "CaseResult",
    "Expectation",
    "HttpProbe",
    "ListingExpectation",
    "Outcome",
    "SetupCall",
    "Step",
    "load_cases",
]
