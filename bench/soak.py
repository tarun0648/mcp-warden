"""The soak test: the gateway under steady, moderate load for a long time.

The latency benchmark answers "what does one call cost?". This answers a different question -
"does the gateway get worse the longer it runs?" - which is where leaks live: a session that is
never closed, a cache that only grows, an audit writer that slows as its table does, a
connection pool that slowly exhausts. Thirty minutes is short for a production soak and long
enough to see any of those as a trend.

What it does:

* runs the real `warden serve` as a **subprocess** against Postgres and Redis, with the shipped
  config except rate limits raised (see `bench.latency.BENCH_LIMITS`; the stage still runs),
  so the memory measured is the gateway's and not this script's;
* drives a fixed mix of calls at a fixed rate from several MCP sessions, including a call the
  policy denies, so the denial and audit paths are soaked too;
* every window, records calls, errors, p50/p95/p99 and the RSS of the gateway's whole process
  tree (the gateway plus the stdio upstreams it spawned);
* at the end, verifies the audit hash chain over every row the run wrote.

Hard rule 7: every number in `results/soak-<date>.md` is computed here from those samples,
including the drift figures. The Markdown is rendered from the JSON.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from redteam.report import machine_info

from bench.latency import BENCH_LIMITS

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"

DEFAULT_MINUTES = 30.0
DEFAULT_RATE = 20.0
DEFAULT_WORKERS = 4
DEFAULT_WINDOW_SECONDS = 60.0
SOAK_DATABASE = "warden_soak"
SOAK_REDIS_DB = 14
PORT = 8099

#: The call mix, cycled in order so every run issues exactly the same sequence. Weighted
#: towards reads, with one call in ten refused by policy so the denial path is soaked too.
MIX: tuple[tuple[str, dict[str, Any], str], ...] = (
    ("notes_db__get_note", {"note_id": 1}, "allowed"),
    ("notes_db__list_notes", {"limit": 5}, "allowed"),
    ("files__read_file", {"path": "soak.md"}, "allowed"),
    ("notes_db__get_note", {"note_id": 2}, "allowed"),
    ("notes_db__search_notes", {"query": "threat"}, "allowed"),
    ("notes_db__get_note", {"note_id": 3}, "allowed"),
    # `path` is passed explicitly. The tool declares it optional with a default of ".", but a
    # policy constraint on an *absent* argument denies (fail-closed), so `{}` is refused. That
    # is a real false positive, recorded under Known gaps in docs/threat-model.md - the soak
    # measures the gateway's stability, not that gap.
    ("files__list_files", {"path": "."}, "allowed"),
    ("notes_db__get_note", {"note_id": 4}, "allowed"),
    ("files__read_file", {"path": "soak.md"}, "allowed"),
    ("files__read_file", {"path": "../../etc/passwd"}, "denied"),
)


# ----------------------------------------------------------------------------------------------
# Measurements and their summary - pure functions, unit tested.
# ----------------------------------------------------------------------------------------------


@dataclass(slots=True)
class Window:
    """One sampling window."""

    index: int
    started_s: float
    calls: int = 0
    errors: int = 0
    unexpected: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    rss_mb: float | None = None
    #: "tool:outcome" -> count, so an unexpected outcome can be traced to the call that caused it.
    outcomes: dict[str, int] = field(default_factory=dict)

    def percentile(self, fraction: float) -> float | None:
        if not self.latencies_ms:
            return None
        ordered = sorted(self.latencies_ms)
        return ordered[min(int(fraction * len(ordered)), len(ordered) - 1)]

    def row(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "minute": round(self.started_s / 60.0, 2),
            "calls": self.calls,
            "errors": self.errors,
            "unexpected": self.unexpected,
            "p50_ms": _round(self.percentile(0.50)),
            "p95_ms": _round(self.percentile(0.95)),
            "p99_ms": _round(self.percentile(0.99)),
            "rss_mb": _round(self.rss_mb),
        }


def _round(value: float | None, places: int = 2) -> float | None:
    return None if value is None else round(value, places)


def slope_per_hour(points: Sequence[tuple[float, float]]) -> float | None:
    """Least-squares slope of (seconds, value) points, expressed per hour."""
    if len(points) < 2:
        return None
    xs = [x for x, _ in points]
    ys = [y for _, y in points]
    mean_x, mean_y = statistics.fmean(xs), statistics.fmean(ys)
    denominator = sum((x - mean_x) ** 2 for x in xs)
    if denominator == 0:
        return None
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    return numerator / denominator * 3600.0


#: Below this, a least-squares slope "per hour" is an extrapolation of noise, not a trend.
MIN_SECONDS_FOR_SLOPE = 600.0


def drift(windows: Sequence[Window], *, edge: int = 5) -> dict[str, Any]:
    """Compare the start of the run with its end.

    The first window is skipped: it contains connection setup and warm-up, and comparing
    against it would report the warm-up as an improvement. Then the next `edge` windows are
    "start" and the last `edge` windows are "end". Memory is also fitted with a straight line,
    because a slow leak shows as a slope long before it shows as a big difference.
    """
    usable = [w for w in windows[1:] if w.calls]
    if len(usable) < 2:
        return {"enough_data": False}
    span = max(1, min(edge, len(usable) // 2))
    start, end = usable[:span], usable[-span:]

    def pooled(group: Sequence[Window], fraction: float) -> float | None:
        values = sorted(v for w in group for v in w.latencies_ms)
        if not values:
            return None
        return values[min(int(fraction * len(values)), len(values) - 1)]

    def mean_rss(group: Sequence[Window]) -> float | None:
        values = [w.rss_mb for w in group if w.rss_mb is not None]
        return statistics.fmean(values) if values else None

    rss_start, rss_end = mean_rss(start), mean_rss(end)
    p95_start, p95_end = pooled(start, 0.95), pooled(end, 0.95)
    p50_start, p50_end = pooled(start, 0.50), pooled(end, 0.50)
    rss_points = [(w.started_s, w.rss_mb) for w in usable if w.rss_mb is not None]
    covered = rss_points[-1][0] - rss_points[0][0] if len(rss_points) > 1 else 0.0
    slope = slope_per_hour(rss_points) if covered >= MIN_SECONDS_FOR_SLOPE else None
    return {
        "enough_data": True,
        "windows_compared": span,
        "rss_start_mb": _round(rss_start),
        "rss_end_mb": _round(rss_end),
        "rss_change_mb": _round(rss_end - rss_start) if rss_start and rss_end else None,
        "rss_change_pct": _round((rss_end - rss_start) / rss_start * 100)
        if rss_start and rss_end
        else None,
        "rss_slope_mb_per_hour": _round(slope),
        "rss_seconds_covered": round(covered, 1),
        "p50_start_ms": _round(p50_start),
        "p50_end_ms": _round(p50_end),
        "p95_start_ms": _round(p95_start),
        "p95_end_ms": _round(p95_end),
        "p95_change_pct": _round((p95_end - p95_start) / p95_start * 100)
        if p95_start and p95_end
        else None,
    }


def second_half_slope(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The RSS slope over the second half of the run only, from per-window rows.

    Added after the first 30-minute run, and reported *alongside* the whole-run slope, never
    instead of it. That run's memory stepped up for nine minutes and then stayed flat for
    twenty; a straight line through all of it reports the warm-up step as a "trend". A leak
    keeps growing after warm-up, so the second half is where it would show. Works from the
    stored rows (minute, rss_mb), so it can be recomputed from any results file.
    """
    points = [
        (row["minute"] * 60.0, row["rss_mb"]) for row in rows if row.get("rss_mb") is not None
    ]
    if len(points) < 4:
        return {"rss_slope_second_half_mb_per_hour": None, "second_half_from_minute": None}
    half = points[len(points) // 2 :]
    covered = half[-1][0] - half[0][0]
    slope = slope_per_hour(half) if covered >= MIN_SECONDS_FOR_SLOPE else None
    return {
        "rss_slope_second_half_mb_per_hour": _round(slope),
        "second_half_from_minute": round(half[0][0] / 60.0, 2),
    }


def totals(windows: Sequence[Window]) -> dict[str, Any]:
    all_latencies = sorted(v for w in windows for v in w.latencies_ms)
    calls = sum(w.calls for w in windows)

    def pct(fraction: float) -> float | None:
        if not all_latencies:
            return None
        return all_latencies[min(int(fraction * len(all_latencies)), len(all_latencies) - 1)]

    outcomes: dict[str, int] = {}
    for window in windows:
        for key, count in window.outcomes.items():
            outcomes[key] = outcomes.get(key, 0) + count
    return {
        "outcomes": dict(sorted(outcomes.items())),
        "calls": calls,
        "errors": sum(w.errors for w in windows),
        "unexpected_outcomes": sum(w.unexpected for w in windows),
        "p50_ms": _round(pct(0.50)),
        "p95_ms": _round(pct(0.95)),
        "p99_ms": _round(pct(0.99)),
        "max_ms": _round(all_latencies[-1] if all_latencies else None),
    }


# ----------------------------------------------------------------------------------------------
# The gateway process and its memory
# ----------------------------------------------------------------------------------------------


def process_tree_rss_mb(root_pid: int) -> float | None:
    """Resident memory of `root_pid` and every descendant, in MiB, from `ps`.

    The tree, not the one process: the stdio upstreams are children of the gateway, and a
    session leak there would be invisible if only the parent were measured.
    """
    try:
        output = subprocess.run(
            ["ps", "-A", "-o", "pid=,ppid=,rss="], capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    children: dict[int, list[int]] = {}
    rss: dict[int, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        pid, ppid, kib = (int(p) for p in parts)
        children.setdefault(ppid, []).append(pid)
        rss[pid] = kib
    if root_pid not in rss:
        return None
    total, stack = 0, [root_pid]
    while stack:
        pid = stack.pop()
        total += rss.get(pid, 0)
        stack.extend(children.get(pid, []))
    return total / 1024.0


def _admin_database_url(database_url: str, name: str) -> tuple[str, str]:
    """(url of the `postgres` maintenance db, url of the soak db) from a base Postgres URL."""
    base = re.sub(r"/[^/?]+(\?.*)?$", "", database_url)
    return f"{base}/postgres", f"{base}/{name}"


async def _recreate_database(admin_url: str, name: str) -> None:
    import asyncpg

    url = admin_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(url)
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()


async def _mint_key(database_url: str) -> str:
    from warden.auth.api_keys import ApiKeyStore
    from warden.db.engine import Database

    database = Database(database_url)
    try:
        generated = await ApiKeyStore(database).create("soak-user", ["editor"], label="soak test")
    finally:
        await database.engine.dispose()
    return str(generated.secret)


@contextlib.contextmanager
def soak_workspace() -> Iterator[Path]:
    workdir = Path(tempfile.mkdtemp(prefix="warden-soak-"))
    try:
        config = workdir / "config"
        shutil.copytree(REPO_ROOT / "config", config)
        gateway = yaml.safe_load((config / "gateway.yaml").read_text())
        gateway["limits"] = {**BENCH_LIMITS, "max_request_body_bytes": 1048576}
        (config / "gateway.yaml").write_text(yaml.safe_dump(gateway, sort_keys=False))
        (workdir / "sandbox").mkdir()
        (workdir / "sandbox" / "soak.md").write_text("A file the soak test reads.\n" * 20)
        (workdir / "data").mkdir()
        (workdir / "keys").mkdir()
        yield workdir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@contextlib.asynccontextmanager
async def gateway_process(
    workdir: Path, database_url: str, redis_url: str, log_path: Path
) -> AsyncIterator[subprocess.Popen[bytes]]:
    env = {
        **os.environ,
        "DATABASE_URL": database_url,
        "REDIS_URL": redis_url,
        "CONFIG_DIR": str(workdir / "config"),
        "JWT_KEY_DIR": str(workdir / "keys"),
        "NOTES_DB_PATH": str(workdir / "data" / "notes.sqlite3"),
        "FILES_SANDBOX_ROOT": str(workdir / "sandbox"),
        "WARDEN_PORT": str(PORT),
        "WARDEN_RESOURCE_URL": f"http://localhost:{PORT}/mcp",
        "JWT_ISSUER": f"http://localhost:{PORT}",
        "JWT_AUDIENCE": f"http://localhost:{PORT}/mcp",
        "LOG_LEVEL": "WARNING",
        "OTEL_ENABLED": "false",
        "CLASSIFIER_ENABLED": "false",
    }
    warden = str(Path(sys.executable).parent / "warden")
    # Setup and teardown block briefly on purpose; they run in a thread so the event loop -
    # which nothing else is using yet - stays honest about it.
    for step in (["db", "upgrade"], ["keys", "init-jwt"]):
        await asyncio.to_thread(
            subprocess.run,
            [warden, *step],
            env=env,
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        )
    log = log_path.open("wb")
    process = await asyncio.to_thread(
        subprocess.Popen,
        [warden, "serve"],
        env=env,
        cwd=REPO_ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        await _wait_ready(f"http://127.0.0.1:{PORT}/readyz", timeout=60)
        yield process
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            await asyncio.to_thread(process.wait, 20)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
        log.close()


async def _wait_ready(url: str, *, timeout: float) -> None:
    import httpx

    deadline = time.monotonic() + timeout
    async with httpx.AsyncClient(timeout=2.0) as client:
        while time.monotonic() < deadline:
            with contextlib.suppress(httpx.HTTPError):
                if (await client.get(url)).status_code == 200:
                    return
            await asyncio.sleep(0.5)
    raise RuntimeError(f"gateway was not ready within {timeout:.0f}s; see the soak log")


# ----------------------------------------------------------------------------------------------
# Load
# ----------------------------------------------------------------------------------------------


async def run_load(
    *,
    url: str,
    key: str,
    minutes: float,
    rate: float,
    workers: int,
    window_seconds: float,
    gateway_pid: int,
) -> list[Window]:
    from agent.demo_agent import classify, connect

    duration = minutes * 60.0
    windows: list[Window] = []
    started = time.monotonic()

    def window_at(now: float) -> Window:
        index = int((now - started) // window_seconds)
        while len(windows) <= index:
            windows.append(Window(index=len(windows), started_s=len(windows) * window_seconds))
        return windows[index]

    async def sampler() -> None:
        while time.monotonic() - started < duration:
            window_at(time.monotonic()).rss_mb = process_tree_rss_mb(gateway_pid)
            await asyncio.sleep(min(window_seconds / 2, 15.0))

    async def worker(offset: int) -> None:
        interval = workers / rate
        next_at = started + offset * (interval / workers)
        position = offset
        async with connect(url, key) as client:
            while True:
                now = time.monotonic()
                if now - started >= duration:
                    return
                if next_at > now:
                    await asyncio.sleep(next_at - now)
                next_at += interval
                tool, arguments, expected = MIX[position % len(MIX)]
                position += workers
                call_started = time.perf_counter()
                try:
                    result = await asyncio.wait_for(client.call_tool(tool, arguments), 30)
                    outcome = classify(result)[0]
                    failed = False
                except Exception:
                    outcome, failed = "error", True
                elapsed_ms = (time.perf_counter() - call_started) * 1000.0
                window = window_at(time.monotonic())
                tally = f"{tool}:{outcome}"
                window.outcomes[tally] = window.outcomes.get(tally, 0) + 1
                window.calls += 1
                window.latencies_ms.append(elapsed_ms)
                if failed:
                    window.errors += 1
                elif outcome != expected:
                    window.unexpected += 1

    await asyncio.gather(sampler(), *(worker(i) for i in range(workers)))
    return [w for w in windows if w.started_s < duration]


def verify_audit(database_url: str, workdir: Path) -> dict[str, Any]:
    env = {**os.environ, "DATABASE_URL": database_url, "CONFIG_DIR": str(workdir / "config")}
    warden = str(Path(sys.executable).parent / "warden")
    completed = subprocess.run(
        [warden, "audit", "verify"], env=env, cwd=REPO_ROOT, capture_output=True, text=True
    )
    match = re.search(r"(\d+) rows verified", completed.stdout)
    return {
        "ok": completed.returncode == 0 and completed.stdout.startswith("OK"),
        "rows_verified": int(match.group(1)) if match else None,
    }


# ----------------------------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------------------------


def render_markdown(payload: dict[str, Any]) -> str:
    cfg, tot, dr, audit = payload["config"], payload["totals"], payload["drift"], payload["audit"]
    machine = payload["machine"]
    lines = [
        f"# Soak test - {payload['generated_at'][:10]}",
        "",
        f"Generated {payload['generated_at']} by `make soak`. Every number below was computed "
        "from the samples in the JSON file next to this one.",
        "",
        f"- machine: {machine.get('chip') or machine.get('processor')}, "
        f"{machine.get('cpu_count')} CPUs, {machine.get('platform')}",
        f"- duration: **{cfg['minutes']} min**, target rate **{cfg['rate']} calls/s** over "
        f"**{cfg['workers']}** MCP sessions, {cfg['window_seconds']:.0f} s windows",
        "- gateway: `warden serve` as a subprocess, Postgres + Redis, full pipeline, classifier "
        "off, rate limits raised so the limiter stage runs without refusing",
        "- mix: " + ", ".join(sorted({tool for tool, _a, _e in MIX})) + "; one call in ten is "
        "a path traversal the policy denies",
        "",
        "## Totals",
        "",
        "| Calls | Errors | Unexpected outcomes | p50 ms | p95 ms | p99 ms | max ms |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        f"| {tot['calls']} | {tot['errors']} | {tot['unexpected_outcomes']} | {tot['p50_ms']} | "
        f"{tot['p95_ms']} | {tot['p99_ms']} | {tot['max_ms']} |",
        "",
        "An *error* is a call that raised or timed out. An *unexpected outcome* is a call that "
        "came back but not as the mix says it should (an allowed call denied, or the traversal "
        "allowed).",
        "",
        "Outcome per tool:",
        "",
        "| tool | outcome | calls |",
        "| --- | --- | --- |",
        *[
            f"| `{key.rsplit(':', 1)[0]}` | {key.rsplit(':', 1)[1]} | {count} |"
            for key, count in tot["outcomes"].items()
        ],
        "",
        "## Drift",
        "",
    ]
    if dr.get("enough_data"):
        lines += [
            f"Start = windows 2-{dr['windows_compared'] + 1} (the first is warm-up and is "
            f"excluded); end = the last {dr['windows_compared']} windows.",
            "",
            "| | Start | End | Change |",
            "| --- | --- | --- | --- |",
            f"| gateway + upstreams RSS (MiB) | {dr['rss_start_mb']} | {dr['rss_end_mb']} | "
            f"{dr['rss_change_mb']} MiB ({dr['rss_change_pct']}%) |",
            f"| p50 latency (ms) | {dr['p50_start_ms']} | {dr['p50_end_ms']} | |",
            f"| p95 latency (ms) | {dr['p95_start_ms']} | {dr['p95_end_ms']} | "
            f"{dr['p95_change_pct']}% |",
            "",
            (
                f"Memory trend (least-squares over every window after the first): "
                f"**{dr['rss_slope_mb_per_hour']} MiB/hour**."
                if dr["rss_slope_mb_per_hour"] is not None
                else f"No memory trend reported: the samples span {dr['rss_seconds_covered']} s, "
                f"under the {MIN_SECONDS_FOR_SLOPE:.0f} s needed for a per-hour slope to mean "
                "anything."
            ),
        ]
        if dr.get("rss_slope_second_half_mb_per_hour") is not None:
            lines += [
                "",
                f"Over the second half only (from minute {dr['second_half_from_minute']}): "
                f"**{dr['rss_slope_second_half_mb_per_hour']} MiB/hour**. Both are reported "
                "because they answer different questions: the first includes warm-up (pools, "
                "caches and allocator arenas filling), the second is where a leak would keep "
                "growing after warm-up has finished. See the per-window table.",
            ]
    else:
        lines.append("Not enough windows to compare start and end.")
    lines += [
        "",
        "## Audit log",
        "",
        f"`warden audit verify` after the run: **{'OK' if audit['ok'] else 'FAILED'}**, "
        f"{audit['rows_verified']} rows verified.",
        "",
        "## Every window",
        "",
        "| # | minute | calls | errors | unexpected | p50 ms | p95 ms | p99 ms | RSS MiB |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in payload["windows"]:
        lines.append(
            f"| {row['index']} | {row['minute']} | {row['calls']} | {row['errors']} | "
            f"{row['unexpected']} | {row['p50_ms']} | {row['p95_ms']} | {row['p99_ms']} | "
            f"{row['rss_mb']} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_report(payload: dict[str, Any], directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = payload["generated_at"][:10]
    json_path = directory / f"soak-{stamp}.json"
    md_path = directory / f"soak-{stamp}.md"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    return json_path, md_path


async def soak(
    *,
    minutes: float,
    rate: float,
    workers: int,
    window_seconds: float,
    base_database_url: str,
    redis_url: str,
    results_dir: Path,
) -> dict[str, Any]:
    admin_url, database_url = _admin_database_url(base_database_url, SOAK_DATABASE)
    await _recreate_database(admin_url, SOAK_DATABASE)
    import redis.asyncio as aioredis

    soak_redis = re.sub(r"/\d+$", "", redis_url) + f"/{SOAK_REDIS_DB}"
    client = aioredis.from_url(soak_redis)
    await client.flushdb()
    await client.aclose()

    with soak_workspace() as workdir:
        log_path = workdir / "gateway.log"
        async with gateway_process(workdir, database_url, soak_redis, log_path) as process:
            key = await _mint_key(database_url)
            print(f"gateway pid {process.pid}; soaking for {minutes} min at {rate} calls/s")
            windows = await run_load(
                url=f"http://localhost:{PORT}/mcp",
                key=key,
                minutes=minutes,
                rate=rate,
                workers=workers,
                window_seconds=window_seconds,
                gateway_pid=process.pid,
            )
        audit = verify_audit(database_url, workdir)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "machine": machine_info(),
        "config": {
            "minutes": minutes,
            "rate": rate,
            "workers": workers,
            "window_seconds": window_seconds,
            "mix": [{"tool": t, "arguments": a, "expected": e} for t, a, e in MIX],
            "limits": "bench.latency.BENCH_LIMITS",
        },
        "totals": totals(windows),
        "drift": {**drift(windows), **second_half_slope([w.row() for w in windows])},
        "audit": audit,
        "windows": [w.row() for w in windows],
    }
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench.soak", description=__doc__.splitlines()[0])
    parser.add_argument("--minutes", type=float, default=DEFAULT_MINUTES)
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE, help="calls per second")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--window-seconds", type=float, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--results-dir", default=str(RESULTS_DIR))
    parser.add_argument(
        "--rerender",
        metavar="JSON",
        help="recompute the derived figures from a stored run and rewrite its Markdown; "
        "measures nothing",
    )
    args = parser.parse_args(argv)

    if args.rerender:
        stored = Path(args.rerender)
        payload = json.loads(stored.read_text(encoding="utf-8"))
        payload["drift"] = {**payload["drift"], **second_half_slope(payload["windows"])}
        stored.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        stored.with_suffix(".md").write_text(render_markdown(payload), encoding="utf-8")
        print(f"re-rendered {stored.with_suffix('.md')} from its stored windows")
        return 0

    from warden.config import Settings

    settings = Settings()
    if not settings.database_url.startswith("postgresql"):
        print("the soak test needs Postgres: set DATABASE_URL (see .env.example)", file=sys.stderr)
        return 2
    payload = asyncio.run(
        soak(
            minutes=args.minutes,
            rate=args.rate,
            workers=args.workers,
            window_seconds=args.window_seconds,
            base_database_url=settings.database_url,
            redis_url=settings.redis_url,
            results_dir=Path(args.results_dir),
        )
    )
    _json_path, md_path = write_report(payload, Path(args.results_dir))
    t = payload["totals"]
    print(f"{t['calls']} calls, {t['errors']} errors, p95 {t['p95_ms']} ms; wrote {md_path}")
    healthy = t["errors"] == 0 and t["unexpected_outcomes"] == 0 and payload["audit"]["ok"]
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MIX",
    "Window",
    "drift",
    "process_tree_rss_mb",
    "second_half_slope",
    "slope_per_hour",
    "totals",
]
