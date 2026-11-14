"""The red-team runner's own logic, with fake cases.

The suite is only worth its numbers if the runner reports honestly, so what is tested here is
the reporting: a pass passes, a miss is a miss, the *wrong* reason code is a miss rather than a
pass, a crashed case is an error rather than a verdict, and a false positive counts against the
score exactly as a missed attack does.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from redteam.model import (
    Case,
    CaseKind,
    CaseResult,
    Expectation,
    Step,
    load_cases,
)
from redteam.report import (
    RunScore,
    compare_with_baseline,
    known_gaps,
    render_markdown,
    write_redteam_report,
)
from redteam.runner import _classify, _match, group_by_profile

pytestmark = pytest.mark.unit


def result(
    case_id: str, *, attack: bool, outcome: str, category: str = "test", detail: str = ""
) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        category=category,
        attack=attack,
        outcome=outcome,  # type: ignore[arg-type]
        detail=detail,
    )


class FakeResult:
    """Stands in for a CallToolResult."""

    def __init__(self, *, is_error: bool, structured: dict[str, Any] | None = None) -> None:
        self.is_error = is_error
        self.structured_content = structured
        self.content: list[Any] = []


# -- classifying what the gateway did ----------------------------------------------------------


def test_a_successful_call_is_allowed() -> None:
    assert _classify(FakeResult(is_error=False)) == (Expectation.ALLOWED, None)


def test_a_warden_denial_is_denied_with_its_code() -> None:
    outcome, code = _classify(
        FakeResult(is_error=True, structured={"error": "WARDEN_DENIED:policy"})
    )
    assert outcome is Expectation.DENIED
    assert code == "WARDEN_DENIED:policy"


def test_a_pending_approval_is_not_a_denial() -> None:
    """Nobody said no, so counting it as a block would overstate the score."""
    outcome, code = _classify(
        FakeResult(is_error=True, structured={"error": "WARDEN_PENDING:approval"})
    )
    assert outcome is Expectation.PENDING
    assert code == "WARDEN_PENDING:approval"


def test_an_upstream_error_is_not_a_gateway_denial() -> None:
    """ "The tool said no" is a different fact from "the gateway said no"."""
    outcome, code = _classify(FakeResult(is_error=True, structured=None))
    assert outcome is Expectation.UPSTREAM_ERROR
    assert code is None


def test_an_error_with_a_non_warden_code_is_an_upstream_error() -> None:
    outcome, _ = _classify(FakeResult(is_error=True, structured={"error": "ENOENT"}))
    assert outcome is Expectation.UPSTREAM_ERROR


# -- matching a step ---------------------------------------------------------------------------


def test_a_matching_step_passes() -> None:
    step = Step(tool="t", expect=Expectation.DENIED, reason="WARDEN_DENIED:policy")
    assert _match(step, Expectation.DENIED, "WARDEN_DENIED:policy") is None


def test_the_wrong_outcome_is_reported() -> None:
    step = Step(tool="t", expect=Expectation.DENIED, reason="WARDEN_DENIED:policy")
    problem = _match(step, Expectation.ALLOWED, None)
    assert problem is not None and "expected denied" in problem


def test_the_wrong_reason_code_is_a_failure_not_a_pass() -> None:
    """The important one: refusing for the wrong reason is how a suite stops measuring."""
    step = Step(tool="t", expect=Expectation.DENIED, reason="WARDEN_DENIED:policy")
    problem = _match(step, Expectation.DENIED, "WARDEN_DENIED:rate_limit")
    assert problem is not None
    assert "WARDEN_DENIED:policy" in problem and "WARDEN_DENIED:rate_limit" in problem


def test_an_allowed_step_needs_no_reason() -> None:
    assert _match(Step(tool="t", expect=Expectation.ALLOWED), Expectation.ALLOWED, None) is None


# -- the case format ---------------------------------------------------------------------------


def test_a_denied_step_must_name_its_reason() -> None:
    with pytest.raises(ValueError, match="must name the expected reason"):
        Step(tool="t", expect=Expectation.DENIED)


def test_an_unknown_reason_code_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a warden reason code"):
        Step(tool="t", expect=Expectation.DENIED, reason="WARDEN_DENIED:invented")


def test_a_tool_call_case_needs_a_step() -> None:
    with pytest.raises(ValueError, match="needs at least one step"):
        Case(id="x-1", category="test", description="a" * 20, attack=True)


def test_a_listing_case_needs_a_listing_block() -> None:
    with pytest.raises(ValueError, match="needs a 'listing' block"):
        Case(
            id="x-1",
            category="test",
            description="a" * 20,
            attack=True,
            kind=CaseKind.LISTING,
        )


def test_an_http_case_needs_an_http_block() -> None:
    with pytest.raises(ValueError, match="needs an 'http' block"):
        Case(id="x-1", category="test", description="a" * 20, attack=True, kind=CaseKind.HTTP)


def test_an_unknown_field_is_rejected() -> None:
    """A typo in a case file must fail at load time, not pass as a case asserting nothing."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="gatewy"):
        Case.model_validate(
            {
                "id": "x-1",
                "category": "test",
                "description": "a" * 20,
                "attack": True,
                "steps": [{"tool": "t", "expect": "allowed"}],
                "gatewy": {},
            }
        )


def test_duplicate_case_ids_are_rejected(tmp_path: Path) -> None:
    body = (
        "cases:\n"
        "  - id: dup-001\n    category: test\n    description: a description here\n"
        "    attack: true\n    steps: [{tool: t, expect: allowed}]\n"
    )
    (tmp_path / "a.yaml").write_text(body)
    (tmp_path / "b.yaml").write_text(body)
    with pytest.raises(ValueError, match="duplicate case id"):
        load_cases(tmp_path)


def test_cases_group_by_their_gateway_overrides() -> None:
    def case(name: str, **kw: Any) -> Case:
        return Case(
            id=name,
            category="test",
            description="a" * 20,
            attack=True,
            steps=[Step(tool="t", expect=Expectation.ALLOWED)],
            **kw,
        )

    groups = group_by_profile(
        [
            case("a-1"),
            case("a-2"),
            case("b-1", gateway={"tools_refresh_seconds": 1.0}),
            case("c-1", evil_variant="base64"),
        ]
    )
    assert len(groups) == 3
    assert sorted(len(g) for g in groups.values()) == [1, 1, 2]


# -- scoring -----------------------------------------------------------------------------------


def test_scoring_counts_attacks_and_benign_separately() -> None:
    score = RunScore(
        label="rules only",
        results=[
            result("a-1", attack=True, outcome="blocked"),
            result("a-2", attack=True, outcome="blocked"),
            result("a-3", attack=True, outcome="missed"),
            result("b-1", attack=False, outcome="allowed"),
            result("b-2", attack=False, outcome="false_positive"),
        ],
    )
    assert score.blocked == 2
    assert score.block_rate == pytest.approx(2 / 3)
    assert score.allowed_benign == 1
    assert score.false_positive_rate == pytest.approx(0.5)


def test_a_false_positive_counts_against_the_run() -> None:
    """A gateway that blocks everything scores 100% on attacks; this is the other half."""
    score = RunScore(label="x", results=[result("b-1", attack=False, outcome="false_positive")])
    assert score.misses and score.misses[0].case_id == "b-1"
    assert score.false_positive_rate == 1.0


def test_an_errored_case_is_neither_blocked_nor_allowed() -> None:
    score = RunScore(
        label="x",
        results=[
            result("a-1", attack=True, outcome="error"),
            result("b-1", attack=False, outcome="error"),
        ],
    )
    assert score.errors == 2
    assert score.blocked == 0
    assert score.allowed_benign == 0
    assert len(score.misses) == 2, "an error is a failure, not an absence of a result"


def test_category_scores_split_by_category() -> None:
    score = RunScore(
        label="x",
        results=[
            result("a-1", attack=True, outcome="blocked", category="dlp"),
            result("a-2", attack=True, outcome="missed", category="dlp"),
            result("b-1", attack=False, outcome="allowed", category="benign"),
        ],
    )
    by_name = {c.category: c for c in score.categories}
    assert by_name["dlp"].attacks == 2 and by_name["dlp"].blocked == 1
    assert by_name["benign"].benign == 1 and by_name["benign"].allowed == 1


def test_known_gaps_lists_only_unblocked_attacks() -> None:
    score = RunScore(
        label="rules only",
        results=[
            result("a-1", attack=True, outcome="missed", detail="got through"),
            result("b-1", attack=False, outcome="false_positive", detail="blocked a read"),
        ],
    )
    gaps = known_gaps([score])
    assert len(gaps) == 1
    assert "a-1" in gaps[0] and "got through" in gaps[0]


# -- the baseline ------------------------------------------------------------------------------


def baseline_of(block_rate: float, false_positive_rate: float) -> dict[str, Any]:
    return {
        "runs": [
            {
                "label": "rules only",
                "block_rate": block_rate,
                "false_positive_rate": false_positive_rate,
            }
        ]
    }


def test_matching_the_baseline_is_not_a_regression() -> None:
    score = RunScore(label="rules only", results=[result("a-1", attack=True, outcome="blocked")])
    assert compare_with_baseline([score], baseline_of(1.0, 0.0)) == []


def test_a_lower_block_rate_is_a_regression() -> None:
    score = RunScore(
        label="rules only",
        results=[
            result("a-1", attack=True, outcome="blocked"),
            result("a-2", attack=True, outcome="missed"),
        ],
    )
    problems = compare_with_baseline([score], baseline_of(1.0, 0.0))
    assert problems and "block rate fell" in problems[0]


def test_more_false_positives_is_a_regression() -> None:
    """Both halves are protected: tightening the gateway until it blocks reads is a regression."""
    score = RunScore(
        label="rules only",
        results=[
            result("a-1", attack=True, outcome="blocked"),
            result("b-1", attack=False, outcome="false_positive"),
        ],
    )
    problems = compare_with_baseline([score], baseline_of(1.0, 0.0))
    assert problems and "false positives rose" in problems[0]


def test_an_improvement_is_not_a_regression() -> None:
    score = RunScore(label="rules only", results=[result("a-1", attack=True, outcome="blocked")])
    assert compare_with_baseline([score], baseline_of(0.5, 0.2)) == []


def test_a_run_absent_from_the_baseline_is_not_a_regression() -> None:
    score = RunScore(label="brand new", results=[result("a-1", attack=True, outcome="missed")])
    assert compare_with_baseline([score], baseline_of(1.0, 0.0)) == []


# -- the report --------------------------------------------------------------------------------


def test_the_report_is_written_as_json_and_markdown(tmp_path: Path) -> None:
    score = RunScore(
        label="rules only",
        results=[
            result("a-1", attack=True, outcome="blocked", category="dlp"),
            result("a-2", attack=True, outcome="missed", category="dlp", detail="slipped past"),
            result("b-1", attack=False, outcome="allowed", category="benign"),
        ],
    )
    json_path, markdown_path = write_redteam_report([score], directory=tmp_path)
    payload = json.loads(json_path.read_text())
    assert payload["runs"][0]["blocked"] == 1
    assert payload["machine"]["python"]
    body = markdown_path.read_text()
    assert "1/2" in body, "the overall table must carry the counted numbers"
    assert "a-2" in body and "slipped past" in body, "a miss must be named in the report"


def test_the_markdown_reports_misses_rather_than_hiding_them() -> None:
    score = RunScore(
        label="rules only",
        results=[result("a-1", attack=True, outcome="missed", detail="got through")],
    )
    body = render_markdown(
        {"generated_at": "now", "machine": _machine(), "runs": [score.as_dict()]}, None
    )
    assert "ATTACK NOT BLOCKED" in body
    assert "a-1" in body


def test_the_markdown_says_so_when_nothing_was_missed() -> None:
    score = RunScore(label="rules only", results=[result("a-1", attack=True, outcome="blocked")])
    body = render_markdown(
        {"generated_at": "now", "machine": _machine(), "runs": [score.as_dict()]}, None
    )
    assert "None. Every attack was blocked" in body


def _machine() -> dict[str, Any]:
    return {
        "chip": "Test chip",
        "processor": "test",
        "platform": "test-platform",
        "python": "3.12.0",
        "cpu_count": 8,
        "packages": {"mcp": "2.3.0"},
    }


# -- the shipped suite -------------------------------------------------------------------------


def test_the_shipped_suite_is_large_and_varied_enough() -> None:
    """The plan asks for 40 attacks across at least ten categories, and 40 benign cases."""
    from redteam.runner import CASES_DIR

    cases = load_cases(CASES_DIR)
    attacks = [c for c in cases if c.attack]
    benign = [c for c in cases if not c.attack]
    categories = {c.category for c in attacks}
    assert len(attacks) >= 40, f"only {len(attacks)} attack cases"
    assert len(benign) >= 40, f"only {len(benign)} benign cases"
    assert len(categories) >= 10, f"only {len(categories)} attack categories: {categories}"


def test_every_shipped_case_names_a_namespaced_tool_or_is_a_probe() -> None:
    """A typo in a tool name would make an attack case pass as WARDEN_UNKNOWN_TOOL."""
    from redteam.runner import CASES_DIR

    for case in load_cases(CASES_DIR):
        for step in case.steps:
            if step.reason == "WARDEN_UNKNOWN_TOOL":
                continue  # these name a missing tool deliberately
            assert "__" in step.tool, f"{case.id}: '{step.tool}' is not namespaced"


def test_the_baseline_file_is_committed_and_parses() -> None:
    """CI compares against it, so a missing or broken baseline silences the regression gate."""
    from redteam.runner import BASELINE

    assert BASELINE.exists(), "results/baseline.json is missing"
    payload = json.loads(BASELINE.read_text())
    labels = {run["label"] for run in payload["runs"]}
    assert "rules only" in labels
    for run in payload["runs"]:
        assert 0.0 <= run["block_rate"] <= 1.0
        assert 0.0 <= run["false_positive_rate"] <= 1.0
