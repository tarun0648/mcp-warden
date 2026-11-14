"""Running the demo scenarios and writing `results/demo-<scenario>.md`.

Each scenario runs five times, as the plan asks, and the report counts two different things:

* **how often the model tried the bad action** - a property of the model, reported for context;
* **how often the gateway stopped it** - a property of the gateway, which is what is asserted.

Keeping those apart is the point. A 7B model does not always take the bait, so "the bad thing
did not happen" is not evidence of anything on its own; "the model tried N times and the
gateway refused N times" is.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent.demo_agent import Agent, Transcript, connect
from agent.llm import LLM, ScriptedLLM, ToolCall
from agent.scenarios.model import Scenario, load_scenarios
from warden.logging import configure_logging, get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = REPO_ROOT / "agent" / "scenarios"
RESULTS_DIR = REPO_ROOT / "results"


@dataclass(slots=True)
class RunOutcome:
    """One run of one scenario, checked against the scenario's expectations."""

    scenario: str
    run: int
    model: str
    transcript: Transcript
    failures: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def passed(self) -> bool:
        return not self.failures

    #: Tool calls the model made that the scenario says must never be allowed. "Tried the bad
    #: action", counted per run rather than per call.
    def bad_attempts(self, scenario: Scenario) -> int:
        wanted = set(scenario.expect.never_allowed)
        return sum(1 for record in self.transcript.steps if record.call.name in wanted)

    def bad_blocked(self, scenario: Scenario) -> int:
        wanted = set(scenario.expect.never_allowed)
        return sum(
            1 for record in self.transcript.steps if record.call.name in wanted and record.blocked
        )


def check(scenario: Scenario, transcript: Transcript, sandbox: Path) -> list[str]:
    """Everything the scenario asserts about the gateway. Returns the failures."""
    problems: list[str] = []
    offered = set(transcript.tools_offered)
    codes = set(transcript.reason_codes())

    for tool in scenario.expect.never_offered:
        if tool in offered:
            problems.append(f"{tool} was offered to the model and should never have been")
    for tool in scenario.expect.offered:
        if tool not in offered:
            problems.append(f"{tool} should have been offered to the model and was not")
    for code in scenario.expect.blocked_with:
        if code not in codes:
            seen = ", ".join(sorted(codes)) or "nothing"
            problems.append(f"expected {code} at least once; the gateway answered {seen}")
    for tool in scenario.expect.never_allowed:
        allowed = [
            record
            for record in transcript.steps
            if record.call.name == tool and record.outcome == "allowed"
        ]
        if allowed:
            problems.append(f"{tool} was ALLOWED through, which the scenario forbids")
    for relative in scenario.expect.files_intact:
        if not (sandbox / relative).exists():
            problems.append(f"{relative} should still exist and does not")
    for relative in scenario.expect.files_absent:
        if (sandbox / relative).exists():
            problems.append(f"{relative} should not exist and does")
    return problems


def scripted_llm(scenario: Scenario) -> ScriptedLLM:
    plan: list[list[ToolCall] | str] = []
    for turn in scenario.script:
        if turn.say is not None:
            plan.append(turn.say)
        else:
            plan.append([ToolCall(name=c.tool, arguments=dict(c.args)) for c in turn.calls])
    return ScriptedLLM(plan)


@contextlib.contextmanager
def scenario_gateway(scenario: Scenario, tmp_path: Path) -> Iterator[Any]:
    """A gateway configured as the scenario asks, with the redteam policy when evil is on."""
    sys.path.insert(0, str(REPO_ROOT))
    from tests.helpers import policies_allowing, running_gateway

    policies = (
        policies_allowing("redteam", "demo-agent-evil", ["evil__*"])
        if scenario.include_evil
        else None
    )
    with running_gateway(
        tmp_path,
        include_evil=scenario.include_evil,
        evil_timeout=10.0,
        evil_env={"EVIL_INJECTION_VARIANT": scenario.evil_variant},
        policies_config=policies,
        gateway_overrides=scenario.gateway,
    ) as gateway:
        yield gateway


async def prepare(scenario: Scenario, gateway: Any, sandbox: Path) -> None:
    """Seed the world the agent will find, and drive any listing refreshes."""
    sys.path.insert(0, str(REPO_ROOT))
    from tests.helpers import approve_tool, gateway_client, pins

    # Files written straight to disk, not through the gateway: see SeedFile's docstring.
    for seed in scenario.seed_files:
        target = sandbox / seed.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(seed.content, encoding="utf-8")

    for tool in scenario.pre_approve:
        approve_tool(gateway, tool)
    for call in scenario.setup:
        async with gateway_client(gateway, gateway.auth(call.role)) as client:
            result = await client.call_tool(call.tool, call.args)
            if result.is_error:
                raise RuntimeError(f"setup call {call.tool} failed: {result.content}")
    if scenario.refresh_listings:
        async with gateway_client(gateway, gateway.auth("admin")) as client:
            for _ in range(scenario.refresh_listings):
                await client.list_tools(cache_mode="bypass")
        # Wait for the gateway's own refresh loop to notice the changed definition.
        deadline = time.monotonic() + 30
        wanted = {c.tool for turn in scenario.script for c in turn.calls}
        while time.monotonic() < deadline:
            if wanted & set(pins(gateway)["quarantined"]):
                return
            await asyncio.sleep(0.25)


async def run_scenario(
    scenario: Scenario,
    *,
    runs: int,
    workdir: Path,
    llm_factory: Any,
    printer: Any | None = None,
) -> list[RunOutcome]:
    """Run one scenario `runs` times, each on a fresh gateway and a fresh sandbox."""
    outcomes: list[RunOutcome] = []
    for index in range(1, runs + 1):
        run_dir = workdir / f"{scenario.name}-{index}"
        run_dir.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        with scenario_gateway(scenario, run_dir) as gateway:
            await prepare(scenario, gateway, run_dir / "sandbox")
            llm: LLM = llm_factory(scenario)
            async with connect(gateway.mcp_url, gateway.keys[scenario.role]) as client:
                transcript = await Agent(client, llm).run(scenario.prompt, printer=printer)
            failures = check(scenario, transcript, run_dir / "sandbox")
        outcomes.append(
            RunOutcome(
                scenario=scenario.name,
                run=index,
                model=transcript.model,
                transcript=transcript,
                failures=failures,
                duration_seconds=round(time.monotonic() - started, 2),
            )
        )
        mark = "ok " if outcomes[-1].passed else "FAIL"
        detail = "; ".join(failures) if failures else "gateway behaved as the scenario requires"
        print(f"  [{mark}] run {index}/{runs}: {detail}")
    return outcomes


# ----------------------------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------------------------


def render_report(scenario: Scenario, outcomes: Sequence[RunOutcome]) -> str:
    from redteam.report import machine_info

    machine = machine_info()
    attempts = sum(o.bad_attempts(scenario) for o in outcomes)
    blocked = sum(o.bad_blocked(scenario) for o in outcomes)
    passed = sum(1 for o in outcomes if o.passed)
    model = outcomes[0].model if outcomes else "unknown"

    lines = [
        f"# Demo scenario: {scenario.title}",
        "",
        f"Generated {datetime.now(UTC).isoformat()} by `make demo SCENARIO={scenario.name}`.",
        "Every number was counted from the runs below.",
        "",
        f"- model: **{model}**",
        f"- runs: **{len(outcomes)}**, of which **{passed}** behaved as the scenario requires",
        f"- machine: {machine.get('chip') or machine.get('processor')}, {machine['platform']}",
        "",
        "## What this shows",
        "",
        scenario.description,
        "",
    ]
    if scenario.expect.layers:
        lines.append("Layers demonstrated:")
        lines.append("")
        for layer in scenario.expect.layers:
            lines.append(f"- {layer}")
        lines.append("")

    lines += [
        "## Counted over every run",
        "",
        "| What | Count |",
        "| --- | --- |",
        f"| times the model attempted a forbidden tool | {attempts} |",
        f"| times the gateway refused it | {blocked} |",
        f"| times a forbidden tool was allowed through | {attempts - blocked} |",
        f"| runs where every gateway expectation held | {passed}/{len(outcomes)} |",
        "",
    ]
    if scenario.expect.never_allowed:
        lines += [
            "The first two rows are different kinds of fact. How often the model took the bait",
            "is a property of the model and is reported for context; how often the gateway",
            "refused is the property under test. A small model that happens not to try is not",
            "evidence that the gateway works, which is why the forbidden-tool count is shown",
            "rather than hidden.",
            "",
        ]

    codes: dict[str, int] = {}
    for outcome in outcomes:
        for code in outcome.transcript.reason_codes():
            codes[code] = codes.get(code, 0) + 1
    if codes:
        lines += ["## Gateway decisions seen", "", "| Reason code | Times |", "| --- | --- |"]
        for code, count in sorted(codes.items()):
            lines.append(f"| `{code}` | {count} |")
        lines.append("")

    failures = [f for outcome in outcomes for f in outcome.failures]
    lines += ["## Failures", ""]
    if failures:
        lines.append("Reported rather than hidden:")
        lines.append("")
        for failure in failures:
            lines.append(f"- {failure}")
    else:
        lines.append("None. Every run met every expectation the scenario sets for the gateway.")
    lines.append("")

    if outcomes:
        lines += ["## One full transcript", "", "```", outcomes[0].transcript.render(), "```", ""]
    return "\n".join(lines)


def write_report(
    scenario: Scenario, outcomes: Sequence[RunOutcome], *, directory: Path
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    markdown = directory / f"demo-{scenario.name}.md"
    markdown.write_text(render_report(scenario, outcomes), encoding="utf-8")
    payload = {
        "scenario": scenario.name,
        "title": scenario.title,
        "generated_at": datetime.now(UTC).isoformat(),
        "runs": [
            {
                "run": o.run,
                "model": o.model,
                "passed": o.passed,
                "failures": o.failures,
                "duration_seconds": o.duration_seconds,
                "bad_attempts": o.bad_attempts(scenario),
                "bad_blocked": o.bad_blocked(scenario),
                "transcript": o.transcript.as_dict(),
            }
            for o in outcomes
        ],
    }
    json_path = directory / f"demo-{scenario.name}.json"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return json_path, markdown


# ----------------------------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent.runner", description="Run the demo scenarios and write results/."
    )
    parser.add_argument(
        "--scenario",
        default="all",
        help="A scenario name, or 'all'.",
    )
    parser.add_argument("--runs", type=int, default=None, help="Override the run count.")
    parser.add_argument(
        "--real-model",
        action="store_true",
        help="Drive the agent with Ollama instead of the scripted model.",
    )
    parser.add_argument("--model", default=None, help="Ollama model; defaults to $OLLAMA_MODEL.")
    parser.add_argument("--quiet", action="store_true", help="Do not print each step.")
    parser.add_argument("--results-dir", default=str(RESULTS_DIR))
    args = parser.parse_args(argv)

    configure_logging("WARNING")
    scenarios = load_scenarios(SCENARIO_DIR)
    if args.scenario != "all":
        if args.scenario not in scenarios:
            print(f"unknown scenario '{args.scenario}'; have {sorted(scenarios)}", file=sys.stderr)
            return 2
        chosen = {args.scenario: scenarios[args.scenario]}
    else:
        chosen = scenarios

    if args.real_model:
        from agent.llm import OllamaLLM

        probe = OllamaLLM(args.model)
        ready, why = asyncio.run(probe.available())
        if not ready:
            print(f"cannot use a real model: {why}", file=sys.stderr)
            print(
                "Install it with `brew install ollama`, start it, then "
                f"`ollama pull {probe.model}`. The scripted runs need none of this.",
                file=sys.stderr,
            )
            return 2

        def factory(_scenario: Scenario) -> LLM:
            return OllamaLLM(args.model)
    else:
        factory = scripted_llm  # type: ignore[assignment]

    from agent.demo_agent import rich_printer

    printer = None if args.quiet else rich_printer()

    import tempfile

    exit_code = 0
    with tempfile.TemporaryDirectory(prefix="warden-demo-") as temp:
        workdir = Path(temp)
        for name, scenario in chosen.items():
            runs = args.runs if args.runs is not None else scenario.runs
            print(f"\n== {name}: {scenario.title} ({runs} runs) ==")
            outcomes = asyncio.run(
                run_scenario(
                    scenario,
                    runs=runs,
                    workdir=workdir,
                    llm_factory=factory,
                    printer=printer,
                )
            )
            _json_path, markdown = write_report(
                scenario, outcomes, directory=Path(args.results_dir)
            )
            print(f"  wrote {markdown}")
            if any(not o.passed for o in outcomes):
                exit_code = 1
    if exit_code:
        print("\nFAIL: at least one run did not meet its gateway expectations", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
