"""The demo scenarios, driven by the scripted model, asserting what the gateway did.

This is the part of the demo that runs in CI. There is no Ollama here and no model download:
`ScriptedLLM` replays the tool calls a model that had taken the bait would make, and every
assertion is about the gateway's answer to those calls. The real-model runs live in
`tests/e2e/test_demo_agent_ollama.py` and are explicitly allowed to be inconsistent, because a
7B model taking the bait is not something a test can require.

Each scenario runs once here. The five-run figures in `results/demo-*.md` come from
`make demo`, which is the same code path - `agent.runner.run_scenario` - so this test failing
means the published reports are no longer reproducible.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from agent.runner import SCENARIO_DIR, render_report, run_scenario, scripted_llm
from agent.scenarios.model import load_scenarios

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

SCENARIOS = load_scenarios(SCENARIO_DIR)
NAMES = sorted(SCENARIOS)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# -- the scenario files themselves -------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_every_scenario_is_loadable_and_asserts_something(name: str) -> None:
    """A scenario with an empty `expect` block would pass no matter what the gateway did."""
    scenario = SCENARIOS[name]
    expect = scenario.expect
    assert (
        expect.blocked_with
        or expect.never_offered
        or expect.never_allowed
        or expect.files_absent
        or expect.offered
        or expect.files_intact
    ), f"{name} asserts nothing about the gateway"
    assert scenario.runs >= 1


def test_the_five_scenarios_the_plan_asks_for_are_present() -> None:
    assert set(NAMES) == {
        "benign",
        "exfiltration",
        "indirect_injection",
        "poisoned_server",
        "rug_pull",
    }


def test_one_scenario_shows_the_system_working_normally() -> None:
    """Without this, every scenario could pass by the gateway refusing everything."""
    benign = SCENARIOS["benign"]
    assert benign.expect.offered
    assert not benign.expect.blocked_with


# -- the runs ----------------------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
async def test_scenario_gateway_decisions(name: str, tmp_path: Path) -> None:
    """Run the scenario and assert every expectation it sets for the gateway."""
    scenario = SCENARIOS[name]
    outcomes = await run_scenario(
        scenario, runs=1, workdir=tmp_path, llm_factory=scripted_llm, printer=None
    )
    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.passed, "\n".join(outcome.failures) + "\n" + outcome.transcript.render()
    assert outcome.model == "scripted"
    assert outcome.transcript.steps, "the agent made no tool calls at all"


async def test_the_attack_scenarios_really_attempted_the_forbidden_tool(tmp_path: Path) -> None:
    """The counting the report relies on.

    A run where the model never tried the bad thing proves nothing, so the scripted runs must
    actually attempt it - and the gateway must refuse every attempt.
    """
    for name in ("exfiltration", "indirect_injection", "poisoned_server", "rug_pull"):
        scenario = SCENARIOS[name]
        outcomes = await run_scenario(
            scenario, runs=1, workdir=tmp_path / name, llm_factory=scripted_llm, printer=None
        )
        outcome = outcomes[0]
        attempts = outcome.bad_attempts(scenario)
        blocked = outcome.bad_blocked(scenario)
        assert attempts >= 1, f"{name}: the script never attempted a forbidden tool"
        assert blocked == attempts, (
            f"{name}: {attempts} attempts, {blocked} refused\n" + outcome.transcript.render()
        )


async def test_a_blocked_step_never_returns_the_upstream_payload(tmp_path: Path) -> None:
    """A denial has to be a denial: the reason code, not the data the tool would have returned."""
    scenario = SCENARIOS["exfiltration"]
    outcomes = await run_scenario(
        scenario, runs=1, workdir=tmp_path, llm_factory=scripted_llm, printer=None
    )
    blocked = [step for step in outcomes[0].transcript.steps if step.blocked]
    assert blocked
    for step in blocked:
        assert step.reason_code is not None and step.reason_code.startswith("WARDEN_")
        assert "exfiltrated" not in step.text.lower()


async def test_the_report_quotes_only_counted_numbers(tmp_path: Path) -> None:
    """Hard rule 7, checked on the generator rather than on a file someone could edit."""
    scenario = SCENARIOS["exfiltration"]
    outcomes = await run_scenario(
        scenario, runs=1, workdir=tmp_path, llm_factory=scripted_llm, printer=None
    )
    report = render_report(scenario, outcomes)
    attempts = outcomes[0].bad_attempts(scenario)
    blocked = outcomes[0].bad_blocked(scenario)
    assert f"| times the model attempted a forbidden tool | {attempts} |" in report
    assert f"| times the gateway refused it | {blocked} |" in report
    assert "| runs where every gateway expectation held | 1/1 |" in report
    assert "None. Every run met every expectation" in report


async def test_a_failing_expectation_is_reported_not_swallowed(tmp_path: Path) -> None:
    """The runner must be able to fail. A harness that always passes is not a harness.

    The scenario is altered to demand a reason code the gateway will not produce, and the run
    has to come back failed with that stated in the report.
    """
    scenario = SCENARIOS["benign"].model_copy(
        update={
            "expect": SCENARIOS["benign"].expect.model_copy(
                update={"blocked_with": ["WARDEN_DENIED:never_happens"]}
            )
        }
    )
    outcomes = await run_scenario(
        scenario, runs=1, workdir=tmp_path, llm_factory=scripted_llm, printer=None
    )
    assert not outcomes[0].passed
    assert any("WARDEN_DENIED:never_happens" in failure for failure in outcomes[0].failures)
    assert "Reported rather than hidden" in render_report(scenario, outcomes)


# -- what the agent is shown -------------------------------------------------------------------


async def test_the_agent_is_only_offered_tools_its_policy_allows(tmp_path: Path) -> None:
    """tools/list is a security boundary, not a convenience: the editor never sees evil__*."""
    scenario = SCENARIOS["poisoned_server"]
    outcomes = await run_scenario(
        scenario, runs=1, workdir=tmp_path, llm_factory=scripted_llm, printer=None
    )
    offered = outcomes[0].transcript.tools_offered
    assert offered, "the agent was offered nothing, so the scenario proves nothing"
    assert not [name for name in offered if name.startswith("evil__")]


async def test_a_poisoned_description_never_reaches_the_model_verbatim(tmp_path: Path) -> None:
    """Either the definition scanner quarantined it, or the agent cleaned it. Never raw."""
    scenario = SCENARIOS["poisoned_server"]
    outcomes = await run_scenario(
        scenario, runs=1, workdir=tmp_path, llm_factory=scripted_llm, printer=None
    )
    for definition in outcomes[0].transcript.tool_definitions:
        text = definition.get("function", {}).get("description", "")
        assert "\u200b" not in text
        assert "\n" not in text
