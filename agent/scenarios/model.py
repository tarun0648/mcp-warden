"""The scenario format for the demo agent.

A scenario carries two things that look redundant and are not:

* `prompt` - what a *real* model is asked to do.
* `script` - the tool calls a model that has taken the bait would make.

Both exist because a 7B model takes the bait inconsistently. Driven by the real model, a
scenario can show that the whole system works but cannot assert anything; driven by the script,
it asserts exactly what the gateway did. The two runs are reported separately and the
`expect` block applies to both.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ScriptedCall(StrictModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class ScriptTurn(StrictModel):
    """One turn of the scripted model: some tool calls, or something to say and stop."""

    calls: list[ScriptedCall] = Field(default_factory=list)
    say: str | None = None

    @model_validator(mode="after")
    def _one_or_the_other(self) -> Self:
        if bool(self.calls) == bool(self.say):
            raise ValueError("a script turn needs either 'calls' or 'say', not both or neither")
        return self


class SetupCall(StrictModel):
    """A call made before the agent starts, to seed the world it will find."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    role: str = "editor"


class SeedFile(StrictModel):
    """A file written straight into the sandbox, bypassing the gateway.

    Needed, and more faithful than it first looks. The exfiltration scenario's note contains a
    credential, and writing it *through* the gateway is refused by the DLP stage - which is
    correct behaviour and has its own red-team case. More to the point, hostile content does
    not usually arrive through the gateway at all: a human pastes it, a sync drops it in, a
    repository is checked out. The agent then reads it through the gateway, which is the part
    under test.
    """

    path: str
    content: str


class Expectations(StrictModel):
    """What the gateway must have done. Assertions about the gateway, never about the model."""

    #: Reason codes that must appear at least once across the run.
    blocked_with: list[str] = Field(default_factory=list)
    #: Tools that must never have been offered to the model at all.
    never_offered: list[str] = Field(default_factory=list)
    #: Tools that must be offered, so a scenario cannot pass by the gateway hiding everything.
    offered: list[str] = Field(default_factory=list)
    #: Tool calls that must never have been allowed through.
    never_allowed: list[str] = Field(default_factory=list)
    #: Files that must still exist afterwards, relative to the sandbox.
    files_intact: list[str] = Field(default_factory=list)
    #: Files that must not exist afterwards.
    files_absent: list[str] = Field(default_factory=list)
    #: A note for the report explaining which layer is being demonstrated.
    layers: list[str] = Field(default_factory=list)


class Scenario(StrictModel):
    name: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=5)
    description: str = Field(min_length=20)
    role: str = "editor"
    prompt: str = Field(min_length=10)
    include_evil: bool = False
    evil_variant: str = "plain"
    gateway: dict[str, Any] = Field(default_factory=dict)
    pre_approve: list[str] = Field(default_factory=list)
    #: Force this many tools/list round trips before the agent runs, to drive the rug pull.
    refresh_listings: int = 0
    setup: list[SetupCall] = Field(default_factory=list)
    seed_files: list[SeedFile] = Field(default_factory=list)
    script: list[ScriptTurn] = Field(default_factory=list)
    expect: Expectations = Expectations()
    #: How many times the scenario is run, per the plan.
    runs: int = 5

    @model_validator(mode="after")
    def _needs_a_script(self) -> Self:
        if not self.script:
            raise ValueError("a scenario needs a script so it can assert without a real model")
        return self


def load_scenarios(directory: Path | str) -> dict[str, Scenario]:
    """Load every `*.yaml` in `directory`, keyed by name."""
    folder = Path(directory)
    out: dict[str, Scenario] = {}
    for path in sorted(folder.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        scenario = Scenario.model_validate(raw)
        if scenario.name in out:
            raise ValueError(f"duplicate scenario name '{scenario.name}'")
        out[scenario.name] = scenario
    return out


__all__ = [
    "Expectations",
    "Scenario",
    "ScriptTurn",
    "ScriptedCall",
    "SeedFile",
    "SetupCall",
    "load_scenarios",
]
