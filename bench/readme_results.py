"""Generate the results tables in README.md and CHANGELOG.md from results/.

Hard rule 7 says the README quotes results/ files and never types a number. This is how: the
block between `<!-- results:start -->` and `<!-- results:end -->` is replaced wholesale by
what this script renders from the newest file of each kind. Nothing in that block is written
by hand, and `--check` (run by the test suite) fails if anyone tries.

The rendering is deterministic - no "generated at" clock - so the check is stable: the same
results files always produce the same block.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"
TARGETS = (REPO_ROOT / "README.md", REPO_ROOT / "CHANGELOG.md")
START = "<!-- results:start -->"
END = "<!-- results:end -->"
BLOCK = re.compile(re.escape(START) + r".*?" + re.escape(END), re.S)
DEMO_ORDER = ("benign", "indirect_injection", "poisoned_server", "exfiltration", "rug_pull")


def newest(directory: Path, prefix: str) -> Path | None:
    """The newest `<prefix>-YYYY-MM-DD.json`; ISO dates sort as strings."""
    candidates = sorted(directory.glob(f"{prefix}-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].json"))
    return candidates[-1] if candidates else None


def load(path: Path | None) -> dict[str, Any] | None:
    return json.loads(path.read_text(encoding="utf-8")) if path else None


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def _link(path: Path) -> str:
    """A README-relative link to the Markdown report next to `path`, else to the JSON."""
    target = path.with_suffix(".md") if path.with_suffix(".md").is_file() else path
    return f"[`results/{target.name}`](results/{target.name})"


def render_redteam(path: Path, data: dict[str, Any]) -> list[str]:
    lines = [
        f"**Red team** - {_link(path)}",
        "",
        "| Configuration | Attacks blocked | Attack categories | Benign allowed "
        "| False positives |",
        "| --- | --- | --- | --- | --- |",
    ]
    for run in data["runs"]:
        categories = sum(1 for c in run["categories"] if c["attacks"] > 0)
        lines.append(
            f"| {run['label']} | {run['blocked']}/{run['attacks']} ({_pct(run['block_rate'])}) | "
            f"{categories} | {run['benign_allowed']}/{run['benign']} | "
            f"{_pct(run['false_positive_rate'])} |"
        )
    return lines


def render_bench(path: Path, data: dict[str, Any]) -> list[str]:
    machine = data["machine"]
    direct = next(
        s for s in data["samples"] if s["configuration"] == "direct" and s["concurrency"] == 1
    )
    lines = [
        f"**Latency added by the gateway** - {_link(path)} - {data['calls']} calls of "
        f"`{data['tool']}` per measurement on {machine.get('chip') or machine['processor']}",
        "",
        f"Direct to the upstream, one call at a time: p50 {_ms(direct['p50_ms'])} ms. "
        "Added on top of that:",
        "",
        "| Configuration | Concurrency | p50 added (ms) | p95 added (ms) | p99 added (ms) |",
        "| --- | --- | --- | --- | --- |",
    ]
    for key, value in data["overhead"].items():
        configuration, concurrency = key.rsplit("@", 1)
        lines.append(
            f"| {configuration} | {concurrency} | {_ms(value['p50_added_ms'])} | "
            f"{_ms(value['p95_added_ms'])} | {_ms(value['p99_added_ms'])} |"
        )
    return lines


def render_soak(path: Path, data: dict[str, Any]) -> list[str]:
    cfg, tot, dr, audit = data["config"], data["totals"], data["drift"], data["audit"]
    lines = [
        f"**Soak** - {_link(path)} - {cfg['minutes']:g} min at {cfg['rate']:g} calls/s",
        "",
        "| Calls | Errors | Unexpected | p50 ms | p95 ms | p99 ms "
        "| RSS start -> end (MiB) | RSS trend | Audit chain |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    trend = (
        f"{dr['rss_slope_mb_per_hour']} MiB/h whole run"
        if dr.get("enough_data") and dr.get("rss_slope_mb_per_hour") is not None
        else "-"
    )
    if dr.get("rss_slope_second_half_mb_per_hour") is not None:
        trend += f"; {dr['rss_slope_second_half_mb_per_hour']} MiB/h second half"
    rss = f"{dr['rss_start_mb']} -> {dr['rss_end_mb']}" if dr.get("enough_data") else "-"
    lines.append(
        f"| {tot['calls']} | {tot['errors']} | {tot['unexpected_outcomes']} | "
        f"{_ms(tot['p50_ms'])} | {_ms(tot['p95_ms'])} | {_ms(tot['p99_ms'])} | {rss} | {trend} | "
        f"{'verified' if audit['ok'] else 'FAILED'}, {audit['rows_verified']} rows |"
    )
    return lines


def render_demos(paths: dict[str, Path]) -> list[str]:
    lines = [
        "**Attack scenarios** - scripted model, so every run actually attempts the attack - "
        "`results/demo-*.md`",
        "",
        "| Scenario | Runs as required | Forbidden calls attempted | Refused | Gateway decision |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name in DEMO_ORDER:
        if name not in paths:
            continue
        data = load(paths[name])
        assert data is not None
        runs = data["runs"]
        attempts = sum(r["bad_attempts"] for r in runs)
        blocked = sum(r["bad_blocked"] for r in runs)
        codes = sorted(
            {
                step["reason_code"]
                for r in runs
                for step in r["transcript"]["steps"]
                if step.get("reason_code")
            }
        )
        lines.append(
            f"| [{name}](results/{paths[name].stem}.md) | "
            f"{sum(1 for r in runs if r['passed'])}/{len(runs)} | {attempts} | {blocked} | "
            f"{', '.join(f'`{c}`' for c in codes) or 'allowed, as it should be'} |"
        )
    return lines


def render_images(path: Path, data: dict[str, Any]) -> list[str]:
    parts = [
        f"{name} {info['content_mib']} MiB compressed ({info['disk']} unpacked)"
        for name, info in data["images"].items()
        if info.get("content_mib")
    ]
    return [f"**Container images** - {_link(path)} - " + "; ".join(parts)]


def render(directory: Path = RESULTS_DIR) -> str:
    sections: list[list[str]] = []
    if (path := newest(directory, "redteam")) and (data := load(path)):
        sections.append(render_redteam(path, data))
    if (path := newest(directory, "bench")) and (data := load(path)):
        sections.append(render_bench(path, data))
    if (path := newest(directory, "soak")) and (data := load(path)):
        sections.append(render_soak(path, data))
    demos = {p.stem[len("demo-") :]: p for p in sorted(directory.glob("demo-*.json"))}
    if demos:
        sections.append(render_demos(demos))
    if (path := newest(directory, "images")) and (data := load(path)):
        sections.append(render_images(path, data))
    if not sections:
        body = "No results yet. Run `make redteam`, `make bench`, `make soak` and `make demo`."
    else:
        body = "\n\n".join("\n".join(section) for section in sections)
    return (
        f"{START}\n"
        "<!-- Generated by `make readme-results` from results/. Do not edit by hand. -->\n\n"
        f"{body}\n\n{END}"
    )


def apply(text: str, block: str) -> str:
    if not BLOCK.search(text):
        raise ValueError(f"no {START} ... {END} block to replace")
    return BLOCK.sub(lambda _m: block, text, count=1)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bench.readme_results", description=__doc__.splitlines()[0]
    )
    parser.add_argument("--check", action="store_true", help="fail if a target is out of date")
    args = parser.parse_args(argv)
    block = render()
    stale = []
    for target in TARGETS:
        if not target.is_file():
            continue
        current = target.read_text(encoding="utf-8")
        updated = apply(current, block)
        if updated != current:
            if args.check:
                stale.append(target.name)
            else:
                target.write_text(updated, encoding="utf-8")
                print(f"updated {target.relative_to(REPO_ROOT)}")
    if stale:
        print(f"out of date: {', '.join(stale)}; run `make readme-results`", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
