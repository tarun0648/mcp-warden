"""What a scanner reports, and how a pile of reports becomes a verdict.

A finding is deliberately small: a rule name, a weight, and a short piece of evidence. Weights
are summed and compared against two thresholds from `gateway.yaml`, so an operator can retune
sensitivity without editing code, and so no single rule can quarantine a tool on its own unless
it is weighted to.

Evidence is always *excerpted and escaped*. A scanner that quoted hostile text verbatim into a
log line, an audit row or a CLI table would hand the attacker a second channel into whoever is
reading the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

MAX_EVIDENCE_CHARS: Final = 120


class Verdict(StrEnum):
    """How bad the scan looks overall."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Severity:
    """Weights, named so a rule's importance is visible where it is declared."""

    #: Worth noting, never decisive on its own.
    LOW: Final = 1
    #: Two of these reach `suspicious`.
    MEDIUM: Final = 2
    #: One of these plus anything else reaches `malicious` at the shipped thresholds.
    HIGH: Final = 3
    #: Enough on its own.
    CRITICAL: Final = 5


def excerpt(text: str, *, limit: int = MAX_EVIDENCE_CHARS) -> str:
    """A short, printable, non-executable rendering of hostile text.

    Control characters and anything invisible become `<U+XXXX>`, so evidence cannot smuggle a
    newline into a JSON log line or hide half of itself from an operator reading a table.
    """
    rendered: list[str] = []
    for char in text[:limit]:
        if char in "\r\n\t":
            rendered.append(" ")
        elif char.isprintable():
            rendered.append(char)
        else:
            rendered.append(f"<U+{ord(char):04X}>")
    out = "".join(rendered)
    return out + ("..." if len(text) > limit else "")


@dataclass(frozen=True, slots=True)
class Finding:
    """One rule firing once."""

    rule: str
    severity: int
    evidence: str
    #: Where in the scanned object the rule fired: "description", "inputSchema.path", "result".
    where: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "evidence": self.evidence,
            "where": self.where,
        }


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Every finding from one scan, plus the verdict they add up to."""

    findings: tuple[Finding, ...] = field(default_factory=tuple)
    verdict: Verdict = Verdict.CLEAN
    score: int = 0
    #: The classifier's probability, when it ran. None means it did not.
    classifier_score: float | None = None

    @property
    def clean(self) -> bool:
        return self.verdict is Verdict.CLEAN

    @property
    def malicious(self) -> bool:
        return self.verdict is Verdict.MALICIOUS

    @property
    def rules(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(finding.rule for finding in self.findings))

    def as_dict(self) -> dict[str, Any]:
        """The shape that reaches `ctx.scan_flags` and so the audit log."""
        body: dict[str, Any] = {
            "verdict": str(self.verdict),
            "score": self.score,
            "rules": list(self.rules),
            "findings": [finding.as_dict() for finding in self.findings],
        }
        if self.classifier_score is not None:
            body["classifier_score"] = round(self.classifier_score, 4)
        return body

    def summary(self) -> str:
        if not self.findings:
            return "clean"
        return f"{self.verdict} (score {self.score}): {', '.join(self.rules)}"


def score_findings(
    findings: tuple[Finding, ...] | list[Finding],
    *,
    suspicious_at: int,
    malicious_at: int,
    classifier_score: float | None = None,
) -> ScanReport:
    """Sum the weights and pick a verdict.

    Each rule contributes at most once however many times it fired: a description with forty
    zero-width characters is one unicode problem, not forty, and otherwise a single noisy rule
    could outvote every other signal.
    """
    ordered = tuple(findings)
    per_rule: dict[str, int] = {}
    for finding in ordered:
        per_rule[finding.rule] = max(per_rule.get(finding.rule, 0), finding.severity)
    score = sum(per_rule.values())
    if score >= malicious_at:
        verdict = Verdict.MALICIOUS
    elif score >= suspicious_at:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN
    return ScanReport(
        findings=ordered, verdict=verdict, score=score, classifier_score=classifier_score
    )


__all__ = [
    "MAX_EVIDENCE_CHARS",
    "Finding",
    "ScanReport",
    "Severity",
    "Verdict",
    "excerpt",
    "score_findings",
]
