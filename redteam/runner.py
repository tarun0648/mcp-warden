"""Runs every red-team case against a real gateway and writes `results/`.

How it is put together, and why:

* **Cases are grouped by their gateway overrides.** Most cases share the default profile, so
  the suite starts a handful of gateways rather than one per case. Starting ninety gateways
  would take minutes and prove nothing extra.
* **Two configurations are run and reported side by side**: rules only, and rules plus the
  local classifier. The difference between the columns is the only honest way to say what the
  model is worth, and the classifier column is skipped (not faked) when the weights are absent.
* **The gateway harness is imported from `tests.helpers`.** It already starts the real app
  under uvicorn, in front of real upstream subprocesses, with credentials minted - and a second
  copy of that, living here, would drift from the one the test suite exercises.
* **Nothing is retried.** A flaky security control is a failing security control, and a suite
  that retries hides it.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import httpx

from redteam.credentials import CredentialForge
from redteam.model import Case, CaseKind, CaseResult, Expectation, Step, load_cases
from redteam.report import (
    RunScore,
    compare_with_baseline,
    known_gaps,
    write_redteam_report,
)
from warden.logging import configure_logging, get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = REPO_ROOT / "redteam" / "cases"
RESULTS_DIR = REPO_ROOT / "results"
BASELINE = RESULTS_DIR / "baseline.json"

#: Keeps a case from hanging the suite if a control deadlocks.
CASE_TIMEOUT_SECONDS = 90.0


class CaseRunner:
    """Executes cases against one running gateway."""

    def __init__(self, gateway: Any, forge: CredentialForge) -> None:
        self._gateway = gateway
        self._forge = forge

    async def run(self, case: Case) -> CaseResult:
        started = time.monotonic()
        try:
            async with asyncio.timeout(CASE_TIMEOUT_SECONDS):
                outcome, detail, evidence = await self._dispatch(case)
        except TimeoutError:
            outcome, detail, evidence = (
                "error",
                f"the case did not finish within {CASE_TIMEOUT_SECONDS:g}s",
                [],
            )
        except Exception as exc:
            outcome, detail, evidence = (
                "error",
                f"{type(exc).__name__}: {exc}"[:400],
                [],
            )
        return CaseResult(
            case_id=case.id,
            category=case.category,
            attack=case.attack,
            outcome=outcome,  # type: ignore[arg-type]
            detail=detail,
            evidence=evidence,
            duration_seconds=round(time.monotonic() - started, 4),
        )

    async def _dispatch(self, case: Case) -> tuple[str, str, list[str]]:
        await self._prepare(case)
        if case.kind is CaseKind.HTTP:
            return await self._run_http(case)
        if case.kind is CaseKind.LISTING:
            return await self._run_listing(case)
        return await self._run_steps(case)

    # -- preparation ---------------------------------------------------------------------

    async def _prepare(self, case: Case) -> None:
        from tests.helpers import approve_tool, gateway_client

        for tool in case.pre_approve:
            approve_tool(self._gateway, tool)
        for call in case.setup:
            async with gateway_client(self._gateway, self._gateway.auth(call.role)) as client:
                result = await client.call_tool(call.tool, call.args)
                if result.is_error:
                    raise RuntimeError(f"setup call {call.tool} failed: {_text(result)[:200]}")
        if case.refresh_listings:
            # Drives the rug pull: the evil server flips its description after a fixed number
            # of listings, and the gateway re-pins on its own refresh.
            async with gateway_client(self._gateway, self._gateway.auth("admin")) as client:
                for _ in range(case.refresh_listings):
                    await client.list_tools(cache_mode="bypass")
            await self._wait_for_requarantine(case)

    async def _wait_for_requarantine(self, case: Case, timeout: float = 30.0) -> None:
        """Wait for the gateway's own refresh loop to notice a changed definition."""
        from tests.helpers import pins

        wanted = {step.tool for step in case.steps}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if wanted & set(pins(self._gateway)["quarantined"]):
                return
            await asyncio.sleep(0.25)

    # -- the three kinds -----------------------------------------------------------------

    async def _run_steps(self, case: Case) -> tuple[str, str, list[str]]:
        from tests.helpers import gateway_client

        evidence: list[str] = []
        async with gateway_client(self._gateway, self._gateway.auth(case.role)) as client:
            for index, step in enumerate(case.steps, start=1):
                result = await client.call_tool(step.tool, step.args)
                actual, code = _classify(result)
                evidence.append(
                    f"step {index} {step.tool} -> {actual}" + (f" ({code})" if code else "")
                )
                verdict = _match(step, actual, code)
                if verdict is not None:
                    return self._fail(case, verdict, evidence)
        return self._pass(case, evidence)

    async def _run_listing(self, case: Case) -> tuple[str, str, list[str]]:
        from tests.helpers import gateway_client

        assert case.listing is not None
        async with gateway_client(self._gateway, self._gateway.auth(case.role)) as client:
            listing = await client.list_tools(cache_mode="bypass")
        names = {tool.name for tool in listing.tools}
        evidence = [f"{case.role} sees {len(names)} tools"]
        missing = [tool for tool in case.listing.visible if tool not in names]
        leaked = [tool for tool in case.listing.hidden if tool in names]
        if leaked:
            return self._fail(
                case, f"these tools should be hidden from {case.role}: {leaked}", evidence
            )
        if missing:
            return self._fail(
                case, f"these tools should be visible to {case.role}: {missing}", evidence
            )
        return self._pass(case, evidence)

    async def _run_http(self, case: Case) -> tuple[str, str, list[str]]:
        assert case.http is not None
        credential = self._forge.build(case.http.credential)
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if credential:
            headers["Authorization"] = f"Bearer {credential}"
        response = await asyncio.to_thread(
            httpx.post,
            self._gateway.mcp_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers=headers,
            timeout=20.0,
        )
        evidence = [f"credential '{case.http.credential}' -> HTTP {response.status_code}"]
        if response.status_code != case.http.expect_status:
            return self._fail(
                case,
                f"expected HTTP {case.http.expect_status}, got {response.status_code}",
                evidence,
            )
        return self._pass(case, evidence)

    # -- verdicts ------------------------------------------------------------------------

    def _pass(self, case: Case, evidence: list[str]) -> tuple[str, str, list[str]]:
        return ("blocked" if case.attack else "allowed", "as expected", evidence)

    def _fail(self, case: Case, detail: str, evidence: list[str]) -> tuple[str, str, list[str]]:
        return ("missed" if case.attack else "false_positive", detail, evidence)


def _text(result: Any) -> str:
    for block in result.content or []:
        text = getattr(block, "text", None)
        if text:
            return str(text)
    return ""


def _classify(result: Any) -> tuple[Expectation, str | None]:
    """What the gateway actually did with a call."""
    if not result.is_error:
        return Expectation.ALLOWED, None
    body = result.structured_content or {}
    code = body.get("error") if isinstance(body, dict) else None
    if isinstance(code, str) and code.startswith("WARDEN_PENDING"):
        return Expectation.PENDING, code
    if isinstance(code, str) and code.startswith("WARDEN_"):
        return Expectation.DENIED, code
    # An is_error result with no warden code is the upstream tool answering "no".
    return Expectation.UPSTREAM_ERROR, None


def _match(step: Step, actual: Expectation, code: str | None) -> str | None:
    """None when the step matched, else why it did not."""
    if actual is not step.expect:
        return f"step expected {step.expect} but the gateway returned {actual}" + (
            f" ({code})" if code else ""
        )
    if step.reason and code != step.reason:
        return f"expected reason {step.reason} but got {code}"
    return None


# ----------------------------------------------------------------------------------------------
# Driving the whole suite
# ----------------------------------------------------------------------------------------------


def group_by_profile(cases: Sequence[Case]) -> dict[str, list[Case]]:
    groups: dict[str, list[Case]] = {}
    for case in cases:
        groups.setdefault(case.profile_key, []).append(case)
    return groups


@contextlib.contextmanager
def redteam_gateway(
    tmp_path: Path,
    overrides: dict[str, Any],
    *,
    classifier: bool,
    evil_variant: str = "plain",
) -> Iterator[Any]:
    """A gateway with the evil server enabled and the red-team policy in force."""
    from tests.helpers import policies_allowing, running_gateway

    policies = policies_allowing("redteam", "redteam-suite-evil", ["evil__*"])
    with running_gateway(
        tmp_path,
        include_evil=True,
        evil_timeout=10.0,
        evil_env={"EVIL_INJECTION_VARIANT": evil_variant},
        policies_config=policies,
        gateway_overrides=_with_classifier(overrides, classifier),
        settings_overrides={"classifier_enabled": classifier},
    ) as gateway:
        yield gateway


def _with_classifier(overrides: dict[str, Any], enabled: bool) -> dict[str, Any]:
    merged = dict(overrides)
    scan = dict(merged.get("scan") or {})
    scan["classifier_enabled"] = enabled
    merged["scan"] = scan
    return merged


async def run_suite(
    cases: Sequence[Case], *, label: str, classifier: bool, workdir: Path
) -> RunScore:
    """Run every case, grouping them so gateways are reused."""
    from warden.config import Settings

    score = RunScore(label=label)
    groups = group_by_profile(cases)
    logger.warning(
        "red-team run starting",
        extra={
            "warden": {
                "label": label,
                "cases": len(cases),
                "gateways": len(groups),
                "classifier": classifier,
            }
        },
    )
    for index, (_key, group) in enumerate(sorted(groups.items())):
        profile_dir = workdir / f"{label.replace(' ', '_')}-{index}"
        profile_dir.mkdir(parents=True, exist_ok=True)
        overrides = group[0].gateway
        with redteam_gateway(
            profile_dir,
            overrides,
            classifier=classifier,
            evil_variant=group[0].evil_variant,
        ) as gateway:
            settings: Settings = gateway.app.state.settings
            forge = CredentialForge(
                key_dir=settings.jwt_key_dir,
                issuer=settings.jwt_issuer,
                audience=settings.jwt_audience,
            )
            runner = CaseRunner(gateway, forge)
            for case in group:
                result = await runner.run(case)
                score.results.append(result)
                mark = "ok " if result.passed else "FAIL"
                print(f"  [{mark}] {case.id:<28} {case.category:<22} {result.detail}")
            verified = await gateway.on_server_loop(gateway.app.state.audit.verify())
            score.audit_chains.append((verified.rows_checked, verified.ok))
            if not verified.ok:
                print(f"  [FAIL] audit chain broken at {verified.first_break}")
    return score


def classifier_available(model_id: str) -> bool:
    """True when the classifier can actually run here.

    Checked so the classifier column is *skipped and labelled*, never filled with rules-only
    numbers under a heading that claims the model was involved. The weights must be in the
    local cache: downloading several hundred megabytes in the middle of a benchmark would make
    the first run's timings meaningless.
    """
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError:
        return False
    try:
        from huggingface_hub import try_to_load_from_cache

        cached = try_to_load_from_cache(model_id, "config.json")
    except Exception:
        return False
    # Returns the file path when cached, a sentinel object when known-absent, None when unknown.
    return isinstance(cached, str)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="redteam.runner", description="Run the red-team suite and write results/."
    )
    parser.add_argument(
        "--rules-only",
        action="store_true",
        help="Skip the classifier column, which is what CI does.",
    )
    parser.add_argument(
        "--filter", default=None, help="Only run cases whose id or category contains this."
    )
    parser.add_argument(
        "--results-dir", default=str(RESULTS_DIR), help="Where to write the report."
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write this run to results/baseline.json after it passes.",
    )
    args = parser.parse_args(argv)

    configure_logging("WARNING")
    cases = load_cases(CASES_DIR)
    if args.filter:
        needle = args.filter.lower()
        cases = [c for c in cases if needle in c.id.lower() or needle in c.category.lower()]
    if not cases:
        print("no cases matched", file=sys.stderr)
        return 2

    attacks = sum(1 for c in cases if c.attack)
    print(f"{len(cases)} cases: {attacks} attacks, {len(cases) - attacks} benign\n")

    import tempfile

    runs: list[RunScore] = []
    with tempfile.TemporaryDirectory(prefix="warden-redteam-") as temp:
        workdir = Path(temp)
        print("== rules only ==")
        runs.append(
            asyncio.run(run_suite(cases, label="rules only", classifier=False, workdir=workdir))
        )
        if not args.rules_only:
            from warden.config import ScanConfig

            model = ScanConfig().classifier_model
            if classifier_available(model):
                print("\n== rules + classifier ==")
                runs.append(
                    asyncio.run(
                        run_suite(
                            cases,
                            label="rules + classifier",
                            classifier=True,
                            workdir=workdir,
                        )
                    )
                )
            else:
                print(
                    f"\n== rules + classifier == skipped: {model} is not available locally.\n"
                    "   Run `uv sync --extra ml` and warm the model, then re-run."
                )

    baseline = None
    if BASELINE.exists():
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    results_dir = Path(args.results_dir)
    json_path, markdown_path = write_redteam_report(runs, directory=results_dir, baseline=baseline)
    print(f"\nwrote {json_path}\nwrote {markdown_path}")

    for run in runs:
        print(
            f"{run.label}: blocked {run.blocked}/{len(run.attacks)} "
            f"({run.block_rate:.1%}), false positives "
            f"{len(run.benign) - run.allowed_benign}/{len(run.benign)} "
            f"({run.false_positive_rate:.1%}), errors {run.errors}"
        )

    gaps = known_gaps(runs)
    if gaps:
        print("\nknown gaps (also written to the report):")
        for gap in gaps:
            print(f"  - {gap}")

    exit_code = 0
    if not all(run.audit_ok for run in runs):
        print("\nFAIL: an audit chain did not verify after the attacks", file=sys.stderr)
        exit_code = 1
    if any(run.errors for run in runs):
        print("\nFAIL: some cases errored rather than producing a verdict", file=sys.stderr)
        exit_code = 1
    if baseline is not None:
        regressions = compare_with_baseline(runs, baseline)
        if regressions:
            print("\nFAIL: worse than results/baseline.json", file=sys.stderr)
            for line in regressions:
                print(f"  - {line}", file=sys.stderr)
            exit_code = 1

    if args.update_baseline and exit_code == 0:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(
            json.dumps(
                {"runs": [run.as_dict() for run in runs]},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nupdated {BASELINE}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
