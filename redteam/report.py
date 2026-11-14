"""Turning case results into the files in `results/`.

Hard rule 7: every number here is counted from results the runner produced. Nothing is typed
in, and the Markdown is generated from the same JSON, so the two cannot disagree.
"""

from __future__ import annotations

import json
import platform
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redteam.model import CaseResult


@dataclass(frozen=True, slots=True)
class CategoryScore:
    category: str
    attacks: int
    blocked: int
    benign: int
    allowed: int
    errors: int

    @property
    def block_rate(self) -> float:
        return self.blocked / self.attacks if self.attacks else 1.0

    @property
    def false_positive_rate(self) -> float:
        return (self.benign - self.allowed) / self.benign if self.benign else 0.0


@dataclass(slots=True)
class RunScore:
    """One configuration's score over the whole suite."""

    label: str
    results: list[CaseResult] = field(default_factory=list)
    #: One entry per gateway the run used: (rows verified, chain intact). Every case runs
    #: against a real hash-chained audit log, and after the attacks have been thrown at it the
    #: chain must still verify - an attack that corrupted the log would otherwise score as
    #: "blocked" while destroying the evidence of itself.
    audit_chains: list[tuple[int, bool]] = field(default_factory=list)

    @property
    def audit_ok(self) -> bool:
        return bool(self.audit_chains) and all(ok for _rows, ok in self.audit_chains)

    @property
    def attacks(self) -> list[CaseResult]:
        return [r for r in self.results if r.attack]

    @property
    def benign(self) -> list[CaseResult]:
        return [r for r in self.results if not r.attack]

    @property
    def blocked(self) -> int:
        return sum(1 for r in self.attacks if r.outcome == "blocked")

    @property
    def allowed_benign(self) -> int:
        return sum(1 for r in self.benign if r.outcome == "allowed")

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.outcome == "error")

    @property
    def block_rate(self) -> float:
        return self.blocked / len(self.attacks) if self.attacks else 0.0

    @property
    def false_positive_rate(self) -> float:
        total = len(self.benign)
        return (total - self.allowed_benign) / total if total else 0.0

    @property
    def misses(self) -> list[CaseResult]:
        """Attacks that were not blocked, and benign traffic that was."""
        return [r for r in self.results if not r.passed]

    @property
    def categories(self) -> list[CategoryScore]:
        names = sorted({r.category for r in self.results})
        scores: list[CategoryScore] = []
        for name in names:
            rows = [r for r in self.results if r.category == name]
            attacks = [r for r in rows if r.attack]
            benign = [r for r in rows if not r.attack]
            scores.append(
                CategoryScore(
                    category=name,
                    attacks=len(attacks),
                    blocked=sum(1 for r in attacks if r.outcome == "blocked"),
                    benign=len(benign),
                    allowed=sum(1 for r in benign if r.outcome == "allowed"),
                    errors=sum(1 for r in rows if r.outcome == "error"),
                )
            )
        return scores

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "attacks": len(self.attacks),
            "blocked": self.blocked,
            "block_rate": round(self.block_rate, 4),
            "benign": len(self.benign),
            "benign_allowed": self.allowed_benign,
            "false_positive_rate": round(self.false_positive_rate, 4),
            "errors": self.errors,
            "audit": {
                "gateways": len(self.audit_chains),
                "chains_intact": sum(1 for _rows, ok in self.audit_chains if ok),
                "rows_verified": sum(rows for rows, _ok in self.audit_chains),
            },
            "categories": [
                {
                    "category": c.category,
                    "attacks": c.attacks,
                    "blocked": c.blocked,
                    "block_rate": round(c.block_rate, 4),
                    "benign": c.benign,
                    "benign_allowed": c.allowed,
                    "errors": c.errors,
                }
                for c in self.categories
            ],
            "misses": [
                {
                    "case_id": r.case_id,
                    "category": r.category,
                    "attack": r.attack,
                    "outcome": r.outcome,
                    "detail": r.detail,
                    "evidence": r.evidence,
                }
                for r in self.misses
            ],
            "results": [r.model_dump() for r in self.results],
        }


def machine_info() -> dict[str, Any]:
    """What the numbers were measured on. A benchmark without this is a rumour."""
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "python": sys.version.split()[0],
        "cpu_count": _cpu_count(),
    }
    chip, memory = _mac_hardware()
    if chip:
        info["chip"] = chip
    if memory:
        info["memory_gb"] = memory
    info["packages"] = _package_versions()
    return info


def _cpu_count() -> int:
    import os

    return os.cpu_count() or 0


def _mac_hardware() -> tuple[str | None, float | None]:
    """Chip name and RAM on macOS, via sysctl. Returns (None, None) elsewhere."""
    import subprocess

    if platform.system() != "Darwin":
        return None, None

    def sysctl(key: str) -> str | None:
        try:
            out = subprocess.run(
                ["sysctl", "-n", key], capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.SubprocessError):  # pragma: no cover
            return None
        return out.stdout.strip() or None

    chip = sysctl("machdep.cpu.brand_string")
    raw = sysctl("hw.memsize")
    memory = round(int(raw) / 1024**3, 1) if raw and raw.isdigit() else None
    return chip, memory


def _package_versions() -> dict[str, str]:
    from importlib.metadata import PackageNotFoundError, version

    wanted = ("mcp", "mcp_types", "pydantic", "sqlalchemy", "redis", "transformers", "torch")
    out: dict[str, str] = {}
    for name in wanted:
        try:
            out[name] = version(name)
        except PackageNotFoundError:
            out[name] = "not installed"
    return out


def write_redteam_report(
    runs: Sequence[RunScore], *, directory: Path, baseline: dict[str, Any] | None = None
) -> tuple[Path, Path]:
    """Write `redteam-<date>.json` and `.md`. Returns both paths."""
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    payload: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "machine": machine_info(),
        "runs": [run.as_dict() for run in runs],
    }
    json_path = directory / f"redteam-{stamp}.json"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    markdown_path = directory / f"redteam-{stamp}.md"
    markdown_path.write_text(render_markdown(payload, baseline), encoding="utf-8")
    return json_path, markdown_path


def render_markdown(payload: dict[str, Any], baseline: dict[str, Any] | None) -> str:
    """The human-readable report, rendered from the JSON so the two cannot drift."""
    runs: list[dict[str, Any]] = payload["runs"]
    machine = payload["machine"]
    memory = machine.get("memory_gb")
    hardware = str(machine.get("chip") or machine.get("processor"))
    if memory:
        hardware = f"{hardware}, {memory} GB RAM"
    lines: list[str] = [
        "# Red-team results",
        "",
        f"Generated {payload['generated_at']} by `make redteam`. Every number here was counted",
        "from the run; nothing in this file is typed by hand.",
        "",
        "## Machine",
        "",
        f"- {hardware}",
        f"- {machine['platform']}",
        f"- Python {machine['python']}, mcp {machine['packages'].get('mcp')}",
        "",
        "## Overall",
        "",
        "| Configuration | Attacks blocked | Block rate | Benign allowed "
        "| False positives | Errors |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for run in runs:
        lines.append(
            f"| {run['label']} | {run['blocked']}/{run['attacks']} | "
            f"{run['block_rate']:.1%} | {run['benign_allowed']}/{run['benign']} | "
            f"{run['false_positive_rate']:.1%} | {run['errors']} |"
        )

    if all("audit" in run for run in runs):
        lines += [
            "",
            "## Audit log after the attacks",
            "",
            "Each gateway's hash chain is verified after its cases have run, so an attack that "
            "damaged the log cannot score as blocked.",
            "",
            "| Configuration | Gateways | Chains intact | Rows verified |",
            "| --- | --- | --- | --- |",
        ]
        for run in runs:
            audit = run["audit"]
            lines.append(
                f"| {run['label']} | {audit['gateways']} | {audit['chains_intact']}/"
                f"{audit['gateways']} | {audit['rows_verified']} |"
            )

    lines += ["", "## By category", ""]
    categories = sorted({c["category"] for run in runs for c in run["categories"]})
    header = "| Category | " + " | ".join(f"{run['label']} blocked" for run in runs) + " |"
    lines += [header, "| --- | " + " | ".join("---" for _ in runs) + " |"]
    for category in categories:
        cells: list[str] = []
        for run in runs:
            entry = next((c for c in run["categories"] if c["category"] == category), None)
            if entry is None or entry["attacks"] == 0:
                cells.append(
                    f"{entry['benign_allowed'] if entry else 0} benign allowed"
                    if entry and entry["benign"]
                    else "-"
                )
            else:
                cells.append(f"{entry['blocked']}/{entry['attacks']}")
        lines.append(f"| {category} | " + " | ".join(cells) + " |")

    for run in runs:
        lines += ["", f"## Misses — {run['label']}", ""]
        if not run["misses"]:
            lines.append("None. Every attack was blocked and every benign call was allowed.")
            continue
        lines.append("Reported, not hidden: a suite that drops its own failures measures nothing.")
        lines.append("")
        for miss in run["misses"]:
            kind = "ATTACK NOT BLOCKED" if miss["attack"] else "FALSE POSITIVE"
            lines.append(f"- **{miss['case_id']}** ({miss['category']}) — {kind}")
            lines.append(f"  - {miss['detail']}")
            for item in miss["evidence"]:
                lines.append(f"  - evidence: {item}")

    if baseline is not None:
        lines += ["", "## Against the baseline", ""]
        lines.append("| Configuration | Baseline blocked | Now | Baseline FP | Now |")
        lines.append("| --- | --- | --- | --- | --- |")
        for run in runs:
            previous = next(
                (b for b in baseline.get("runs", []) if b["label"] == run["label"]), None
            )
            if previous is None:
                lines.append(
                    f"| {run['label']} | (new) | {run['block_rate']:.1%} | (new) | "
                    f"{run['false_positive_rate']:.1%} |"
                )
                continue
            lines.append(
                f"| {run['label']} | {previous['block_rate']:.1%} | {run['block_rate']:.1%} "
                f"| {previous['false_positive_rate']:.1%} | {run['false_positive_rate']:.1%} |"
            )
    return "\n".join(lines) + "\n"


def compare_with_baseline(runs: Sequence[RunScore], baseline: dict[str, Any]) -> list[str]:
    """Return a list of regressions. Empty means this run is no worse than the baseline."""
    regressions: list[str] = []
    for run in runs:
        previous = next((b for b in baseline.get("runs", []) if b["label"] == run.label), None)
        if previous is None:
            continue
        if run.block_rate < previous["block_rate"] - 1e-9:
            regressions.append(
                f"{run.label}: block rate fell from {previous['block_rate']:.1%} to "
                f"{run.block_rate:.1%}"
            )
        if run.false_positive_rate > previous["false_positive_rate"] + 1e-9:
            regressions.append(
                f"{run.label}: false positives rose from "
                f"{previous['false_positive_rate']:.1%} to {run.false_positive_rate:.1%}"
            )
    return regressions


def known_gaps(runs: Sequence[RunScore]) -> list[str]:
    """One line per attack that got through, for the threat model's Known gaps list."""
    gaps: list[str] = []
    for run in runs:
        for miss in run.misses:
            if miss.attack:
                gaps.append(f"[{run.label}] {miss.case_id} ({miss.category}): {miss.detail}")
    return gaps


__all__ = [
    "CategoryScore",
    "RunScore",
    "compare_with_baseline",
    "known_gaps",
    "machine_info",
    "render_markdown",
    "write_redteam_report",
]
