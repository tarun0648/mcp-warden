"""The demo scenarios driven by a real local model.

Marked `e2e` and skipped unless Ollama is installed, running and has the model pulled. Nothing
in CI depends on it.

These tests assert much less than the scripted runs in
`tests/integration/test_demo_scenarios.py`, on purpose. A 7B model takes the bait
inconsistently, so "the model tried to exfiltrate the credential" is not something a test can
require - requiring it would mean tuning the prompt until the model misbehaved, which is
exactly the kind of number-fitting hard rule 7 forbids. What *is* asserted is conditional and
still meaningful: whatever the model attempted, the gateway's answer must have been right, and
no forbidden tool may have been allowed through.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from agent.llm import OllamaLLM
from agent.runner import SCENARIO_DIR, run_scenario
from agent.scenarios.model import Scenario, load_scenarios

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]

SCENARIOS = load_scenarios(SCENARIO_DIR)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def ollama() -> OllamaLLM:
    llm = OllamaLLM()
    ready, why = await llm.available()
    if not ready:
        pytest.skip(
            f"no local model: {why}. Install with `brew install ollama`, then "
            f"`ollama pull {llm.model}`."
        )
    return llm


def real_model(_scenario: Scenario) -> OllamaLLM:
    return OllamaLLM()


async def test_the_benign_scenario_completes_with_a_real_model(
    ollama: OllamaLLM, tmp_path: Path
) -> None:
    """The one scenario where the model's behaviour can be asserted: it should just work.

    No attack, no injected instruction - so a model that cannot complete this is a sign the
    gateway is in the way of ordinary use, which is worth failing over.
    """
    outcomes = await run_scenario(
        SCENARIOS["benign"], runs=1, workdir=tmp_path, llm_factory=real_model, printer=None
    )
    transcript = outcomes[0].transcript
    assert transcript.model == ollama.name
    assert transcript.steps, "the model called no tools at all"
    assert not transcript.blocked, "the gateway refused an ordinary call:\n" + transcript.render()


@pytest.mark.parametrize(
    "name", ["exfiltration", "indirect_injection", "poisoned_server", "rug_pull"]
)
async def test_whatever_the_real_model_attempts_the_gateway_answers_correctly(
    ollama: OllamaLLM, name: str, tmp_path: Path
) -> None:
    """Conditional by design, as the docstring at the top of this file explains."""
    scenario = SCENARIOS[name]
    outcomes = await run_scenario(
        scenario, runs=1, workdir=tmp_path, llm_factory=real_model, printer=None
    )
    outcome = outcomes[0]
    rendered = outcome.transcript.render()

    allowed_forbidden = [
        step
        for step in outcome.transcript.steps
        if step.call.name in set(scenario.expect.never_allowed) and step.outcome == "allowed"
    ]
    assert not allowed_forbidden, f"{name}: a forbidden tool was allowed\n{rendered}"

    for tool in scenario.expect.never_offered:
        assert tool not in outcome.transcript.tools_offered, (
            f"{name}: {tool} was offered to the model\n{rendered}"
        )

    for relative in scenario.expect.files_intact:
        assert (tmp_path / f"{name}-1" / "sandbox" / relative).exists(), (
            f"{name}: {relative} was destroyed\n{rendered}"
        )

    attempts = outcome.bad_attempts(scenario)
    if attempts:
        assert outcome.bad_blocked(scenario) == attempts, (
            f"{name}: {attempts} attempts at a forbidden tool, "
            f"{outcome.bad_blocked(scenario)} refused\n{rendered}"
        )
    else:
        pytest.skip(
            f"the model did not take the bait in this run ({attempts} attempts); "
            "nothing to assert about the gateway. The scripted run in "
            "tests/integration/test_demo_scenarios.py covers the decision itself."
        )
