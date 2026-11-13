"""Measured detection and false-positive rates over the labelled set.

Two runs, reported separately, because the difference between them is the only honest way to
say what the classifier is worth:

* **rules only** - always runs, in CI, with no model weights.
* **rules + classifier** - marked `ml`, runs locally with `uv sync --extra ml`.

The thresholds are asserted, not printed and ignored. If a change to the rules drops detection
below the floor or lifts false positives above the ceiling, this test fails and the numbers in
the report are what they are: hard rule 7 says no invented numbers, so the assertion is on
measurements, and the measurements are written where anyone can re-run them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from warden.config import ScanConfig
from warden.scan.findings import Verdict, score_findings
from warden.scan.text_rules import find_cross_tool_references, scan_text

pytestmark = pytest.mark.unit

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

#: The servers and tools a scanner would know about, so cross-tool references are detectable
#: exactly as they are in the running gateway.
KNOWN_SERVERS = ("files", "notes_db", "evil")
KNOWN_TOOLS = (
    "files__read_file",
    "files__write_file",
    "files__delete_file",
    "files__list_files",
    "notes_db__run_sql",
    "notes_db__list_notes",
    "notes_db__delete_note",
    "evil__send_report",
)

#: Floors and ceilings. Rules alone are expected to be good but not complete - the gaps are
#: mostly non-English and heavily obfuscated cases, which is what the classifier is for.
RULES_ONLY_MIN_DETECTION = 0.85
RULES_ONLY_MAX_FALSE_POSITIVES = 0.05
WITH_CLASSIFIER_MIN_DETECTION = 0.85
WITH_CLASSIFIER_MAX_FALSE_POSITIVES = 0.05


@dataclass(frozen=True, slots=True)
class Example:
    label: int
    category: str
    text: str
    #: Which scanner sees this text in the running gateway: a tool *definition* is read by the
    #: definition scanner, which also checks cross-tool references, while a tool *result* is
    #: read by the output scanner, which does not. Measuring both with the same rule set would
    #: either miss shadowing or count a note that mentions "the files server" as a false
    #: positive - neither of which is what the gateway does.
    surface: str = "output"


def load(name: str) -> list[Example]:
    rows = [
        json.loads(line)
        for line in (DATA_DIR / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return [
        Example(row["label"], row["category"], row["text"], row.get("surface", "output"))
        for row in rows
    ]


def rules_verdict(example: Example, config: ScanConfig) -> Verdict:
    """The verdict the rules alone reach, through the scanner that would actually see it."""
    findings = list(scan_text(example.text, where=example.surface))
    if example.surface == "definition":
        findings.extend(
            find_cross_tool_references(
                example.text,
                own_server="unknown",
                other_servers=KNOWN_SERVERS,
                other_tools=KNOWN_TOOLS,
                where="definition",
            )
        )
    return score_findings(
        findings,
        suspicious_at=config.definition_suspicious_score,
        malicious_at=config.definition_malicious_score,
    ).verdict


def flagged(verdict: Verdict) -> bool:
    """ "Detected" means anything other than clean: suspicious wraps, malicious blocks."""
    return verdict is not Verdict.CLEAN


@dataclass(frozen=True, slots=True)
class Rates:
    detected: int
    attacks: int
    false_positives: int
    benign: int
    misses: tuple[Example, ...]
    wrong: tuple[Example, ...]

    @property
    def detection_rate(self) -> float:
        return self.detected / self.attacks if self.attacks else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / self.benign if self.benign else 0.0

    def report(self, label: str) -> str:
        lines = [
            f"{label}: detection {self.detected}/{self.attacks} "
            f"({self.detection_rate:.1%}), false positives {self.false_positives}/{self.benign} "
            f"({self.false_positive_rate:.1%})"
        ]
        for example in self.misses:
            lines.append(f"  MISSED [{example.category}] {example.text[:90]}")
        for example in self.wrong:
            lines.append(f"  FALSE POSITIVE [{example.category}] {example.text[:90]}")
        return "\n".join(lines)


def measure(decide: object) -> Rates:
    attacks = load("injection.jsonl")
    benign = load("benign.jsonl")
    misses = tuple(example for example in attacks if not decide(example))  # type: ignore[operator]
    wrong = tuple(example for example in benign if decide(example))  # type: ignore[operator]
    return Rates(
        detected=len(attacks) - len(misses),
        attacks=len(attacks),
        false_positives=len(wrong),
        benign=len(benign),
        misses=misses,
        wrong=wrong,
    )


# -- the dataset itself ------------------------------------------------------------------------


def test_the_dataset_is_large_and_varied_enough_to_mean_something() -> None:
    attacks = load("injection.jsonl")
    benign = load("benign.jsonl")
    assert len(attacks) >= 40
    assert len(benign) >= 40
    assert len({example.category for example in attacks}) >= 6
    assert len({example.category for example in benign}) >= 4
    assert all(example.label == 1 for example in attacks)
    assert all(example.label == 0 for example in benign)


def test_every_example_declares_which_scanner_sees_it() -> None:
    for example in load("injection.jsonl") + load("benign.jsonl"):
        assert example.surface in ("definition", "output"), example


def test_no_example_appears_in_both_files() -> None:
    attack_texts = {example.text for example in load("injection.jsonl")}
    benign_texts = {example.text for example in load("benign.jsonl")}
    assert not attack_texts & benign_texts


# -- rules only --------------------------------------------------------------------------------


def test_rules_only_rates(capsys: pytest.CaptureFixture[str]) -> None:
    config = ScanConfig()
    rates = measure(lambda example: flagged(rules_verdict(example, config)))
    with capsys.disabled():
        print("\n" + rates.report("rules only"))
    assert rates.detection_rate >= RULES_ONLY_MIN_DETECTION, rates.report("rules only")
    assert rates.false_positive_rate <= RULES_ONLY_MAX_FALSE_POSITIVES, rates.report("rules only")


def test_every_benign_category_is_mostly_clean() -> None:
    """A rule that fires on a whole category of ordinary text is worse than a missed attack."""
    config = ScanConfig()
    benign = load("benign.jsonl")
    by_category: dict[str, list[Example]] = {}
    for example in benign:
        by_category.setdefault(example.category, []).append(example)
    for category, examples in by_category.items():
        hits = [e for e in examples if flagged(rules_verdict(e, config))]
        assert len(hits) <= max(1, len(examples) // 10), (
            f"category '{category}': {len(hits)}/{len(examples)} benign examples flagged: "
            + "; ".join(e.text[:60] for e in hits)
        )


def test_the_hardest_attack_classes_are_covered_by_rules_alone() -> None:
    """These are the classes the gateway must not need a model for."""
    config = ScanConfig()
    attacks = load("injection.jsonl")
    for category in ("tool_poisoning", "shadowing", "encoded", "exfiltration"):
        examples = [e for e in attacks if e.category == category]
        assert examples, f"no examples for {category}"
        missed = [e for e in examples if not flagged(rules_verdict(e, config))]
        assert not missed, f"{category} missed: " + "; ".join(e.text[:70] for e in missed)


# -- rules plus the classifier -----------------------------------------------------------------


@pytest.mark.ml
def test_rules_plus_classifier_rates(capsys: pytest.CaptureFixture[str]) -> None:
    """Needs the model weights: `uv sync --extra ml`, then `pytest -m ml`.

    Both the combined decision and the **classifier alone** are reported. The combined figure
    is what the gateway does; the classifier-alone figure is what the model is worth, and
    hiding it behind the rules would be exactly the kind of flattering number hard rule 7
    exists to prevent. The measurement is also why `classifier_threshold` defaults to 0.999
    rather than 0.8 - see docs/decisions.md.
    """
    import asyncio

    from warden.scan.classifier import InjectionClassifier

    config = ScanConfig(classifier_enabled=True)
    classifier = InjectionClassifier(
        enabled=True,
        model_id=config.classifier_model,
        # The first call downloads the weights, which is not what the timeout is for.
        timeout_seconds=300.0,
    )

    scores: dict[str, float] = {}

    async def score(example: Example) -> float:
        if example.text not in scores:
            outcome = await classifier.classify(example.text)
            if outcome.failed:
                pytest.skip(f"classifier unavailable: {outcome.error}")
            scores[example.text] = outcome.score or 0.0
        return scores[example.text]

    loop = asyncio.new_event_loop()
    try:
        combined = measure(
            lambda example: (
                flagged(rules_verdict(example, config))
                or loop.run_until_complete(score(example)) >= config.classifier_threshold
            )
        )
        classifier_only = measure(
            lambda example: loop.run_until_complete(score(example)) >= config.classifier_threshold
        )
    finally:
        loop.close()

    with capsys.disabled():
        print()
        print(classifier_only.report(f"classifier only (>= {config.classifier_threshold})"))
        print(combined.report("rules + classifier"))

    assert combined.detection_rate >= WITH_CLASSIFIER_MIN_DETECTION, combined.report(
        "rules + classifier"
    )
    assert combined.false_positive_rate <= WITH_CLASSIFIER_MAX_FALSE_POSITIVES, combined.report(
        "rules + classifier"
    )


def test_a_classifier_hit_alone_can_never_block_or_quarantine() -> None:
    """The architectural consequence of the measurement above.

    The model scores ordinary security prose as confidently as it scores real injections, so it
    is weighted as one signal among several: a classifier hit on its own reaches `suspicious`,
    never `malicious`. That keeps a false positive to a warning banner on a trusted server's
    output rather than a refused call, and it is why the gateway is useful with the classifier
    switched off entirely.
    """
    from warden.scan.findings import Finding, Severity

    config = ScanConfig()
    report = score_findings(
        [Finding(rule="classifier:injection", severity=Severity.HIGH, evidence="0.999")],
        suspicious_at=config.definition_suspicious_score,
        malicious_at=config.definition_malicious_score,
    )
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.verdict is not Verdict.MALICIOUS
