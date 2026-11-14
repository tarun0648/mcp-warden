"""What the gateway costs, measured rather than estimated.

Four configurations, each calling the *same* fast read tool so the difference is the gateway
and not the work:

| Configuration | What it isolates |
| --- | --- |
| `direct` | the upstream alone, over Streamable HTTP - the floor |
| `auth+policy` | authenticate, resolve, policy, forward - the cheap half |
| `full (rules)` | every stage, scanners on, classifier off - what ships by default |
| `full (classifier)` | the same with the local model in the output path |

Reported per configuration: p50, p95, p99, mean, throughput, and the overhead added over
`direct`. Sequentially and at concurrency 10 and 50, because a p95 measured one call at a time
says nothing about a gateway under load.

Hard rule 7: every number is measured here and written to `results/` by this script. Nothing is
typed in, and the Markdown is rendered from the JSON so the two cannot disagree.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import statistics
import sys
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redteam.report import machine_info

from warden.logging import configure_logging, get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"

#: The tool every configuration calls: a single indexed row, so the upstream's own work is
#: close to nothing and what is left is the gateway.
TOOL = "notes_db__get_note"
UPSTREAM_TOOL = "get_note"
ARGS = {"note_id": 1}

DEFAULT_CALLS = 1000
DEFAULT_WARMUP = 50
CONCURRENCIES = (1, 10, 50)


@dataclass(slots=True)
class Sample:
    """Latencies for one configuration at one concurrency, in milliseconds."""

    configuration: str
    concurrency: int
    latencies_ms: list[float] = field(default_factory=list)
    errors: int = 0
    wall_seconds: float = 0.0

    def percentile(self, fraction: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        index = min(int(fraction * len(ordered)), len(ordered) - 1)
        return ordered[index]

    @property
    def p50(self) -> float:
        return self.percentile(0.50)

    @property
    def p95(self) -> float:
        return self.percentile(0.95)

    @property
    def p99(self) -> float:
        return self.percentile(0.99)

    @property
    def mean(self) -> float:
        return statistics.fmean(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def throughput(self) -> float:
        """Calls per second actually achieved, wall-clock."""
        return len(self.latencies_ms) / self.wall_seconds if self.wall_seconds else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "configuration": self.configuration,
            "concurrency": self.concurrency,
            "calls": len(self.latencies_ms),
            "errors": self.errors,
            "p50_ms": round(self.p50, 3),
            "p95_ms": round(self.p95, 3),
            "p99_ms": round(self.p99, 3),
            "mean_ms": round(self.mean, 3),
            "throughput_per_second": round(self.throughput, 1),
            "wall_seconds": round(self.wall_seconds, 3),
        }


async def measure(
    session: Any,
    *,
    configuration: str,
    concurrency: int,
    calls: int,
    warmup: int,
) -> Sample:
    """Run `calls` calls spread over `concurrency` independent client sessions.

    One session per concurrent worker, not N requests in flight on one session. That is both
    what a real deployment looks like - each client holds its own session - and necessary:
    fifty concurrent calls multiplexed onto a single Streamable HTTP session serialise behind
    one response stream, so the first attempt at this measured the SDK's session, not the
    gateway, and the slowest calls timed out.

    `session` is an async context manager factory: `async with session() as call` yields a
    coroutine that performs one call and returns whether it succeeded.
    """
    # Warm-up on one session. The first calls pay for the MCP handshake, the SQLite page cache
    # and the JIT-adjacent warming of the import graph; timing them would measure start-up.
    async with session() as call:
        for _ in range(warmup):
            await call()

    sample = Sample(configuration=configuration, concurrency=concurrency)
    per_worker = max(1, calls // concurrency)
    started = time.perf_counter()

    async def worker() -> None:
        async with session() as call:
            for _ in range(per_worker):
                began = time.perf_counter()
                ok = await call()
                sample.latencies_ms.append((time.perf_counter() - began) * 1000)
                if not ok:
                    sample.errors += 1

    await asyncio.gather(*(worker() for _ in range(concurrency)))
    sample.wall_seconds = time.perf_counter() - started
    return sample


# ----------------------------------------------------------------------------------------------
# The four configurations
# ----------------------------------------------------------------------------------------------


@contextlib.contextmanager
def direct_upstream(tmp_path: Path) -> Iterator[str]:
    """The notes server on its own, over Streamable HTTP. The floor to compare against."""
    import os
    import socket
    import subprocess
    from contextlib import closing

    import httpx

    with closing(socket.socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])

    env = dict(os.environ)
    env["NOTES_DB_PATH"] = str(tmp_path / "bench-notes.sqlite3")
    env["PYTHONPATH"] = str(REPO_ROOT)
    process = subprocess.Popen(
        [sys.executable, "-m", "servers.notes_db", "--http", str(port)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                _, err = process.communicate()
                raise RuntimeError(f"notes_db exited: {err.decode()[-500:]}")
            try:
                httpx.get(f"http://127.0.0.1:{port}/mcp", timeout=0.5)
                break
            except httpx.HTTPError:
                time.sleep(0.2)
        else:
            raise RuntimeError("notes_db did not start")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)


#: The benchmark's own HTTP read timeout. Generous on purpose: at concurrency 50 a thousand
#: queued calls legitimately take a while to drain, and the default timeout turned that queue
#: into a read error - which measures the client's patience, not the gateway.
CLIENT_TIMEOUT_SECONDS = 180.0


def _session_factory(url: str, headers: dict[str, str] | None = None) -> Any:
    """`async with factory() as call` -> a coroutine making one tool call on a fresh session."""
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    tool = UPSTREAM_TOOL if headers is None else TOOL

    @contextlib.asynccontextmanager
    async def factory() -> Any:
        async with (
            httpx2.AsyncClient(headers=headers or {}, timeout=CLIENT_TIMEOUT_SECONDS) as http,
            Client(streamable_http_client(url, http_client=http)) as client,
        ):

            async def call() -> bool:
                try:
                    result = await client.call_tool(tool, ARGS)
                except Exception:
                    logger.warning("benchmark call failed", exc_info=True)
                    return False
                return not result.is_error

            yield call

    return factory


async def bench_direct(url: str, concurrency: int, calls: int, warmup: int) -> Sample:
    return await measure(
        _session_factory(url),
        configuration="direct",
        concurrency=concurrency,
        calls=calls,
        warmup=warmup,
    )


@contextlib.contextmanager
def gateway_for(tmp_path: Path, *, label: str, stages: Sequence[str] | None, classifier: bool):  # type: ignore[no-untyped-def]
    """A gateway with the requested pipeline, measured as a client would see it."""
    sys.path.insert(0, str(REPO_ROOT))
    from tests.helpers import running_gateway

    workdir = tmp_path / label.replace(" ", "_").replace("+", "-").replace("(", "").replace(")", "")
    workdir.mkdir(parents=True, exist_ok=True)
    with running_gateway(
        workdir,
        gateway_overrides={
            "scan": {"classifier_enabled": classifier},
            "limits": BENCH_LIMITS,
        },
        settings_overrides={"classifier_enabled": classifier},
        pipeline_stages=stages,
    ) as gateway:
        yield gateway


async def bench_gateway(
    gateway: Any, *, label: str, concurrency: int, calls: int, warmup: int
) -> Sample:
    return await measure(
        _session_factory(gateway.mcp_url, headers=gateway.auth("editor")),
        configuration=label,
        concurrency=concurrency,
        calls=calls,
        warmup=warmup,
    )


# ----------------------------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------------------------


def overhead(samples: Sequence[Sample]) -> dict[str, dict[str, float]]:
    """Added latency over `direct`, per configuration and concurrency."""
    floor = {s.concurrency: s for s in samples if s.configuration == "direct"}
    out: dict[str, dict[str, float]] = {}
    for sample in samples:
        if sample.configuration == "direct":
            continue
        base = floor.get(sample.concurrency)
        if base is None:
            continue
        key = f"{sample.configuration}@{sample.concurrency}"
        out[key] = {
            "p50_added_ms": round(sample.p50 - base.p50, 3),
            "p95_added_ms": round(sample.p95 - base.p95, 3),
            "p99_added_ms": round(sample.p99 - base.p99, 3),
        }
    return out


def render_markdown(payload: dict[str, Any]) -> str:
    machine = payload["machine"]
    memory = machine.get("memory_gb")
    hardware = str(machine.get("chip") or machine.get("processor"))
    if memory:
        hardware = f"{hardware}, {memory} GB RAM"
    samples: list[dict[str, Any]] = payload["samples"]
    lines = [
        "# Latency benchmark",
        "",
        f"Generated {payload['generated_at']} by `make bench`. Every number was measured by",
        "`bench/latency.py` on the machine below; nothing here is typed by hand.",
        "",
        "## Machine",
        "",
        f"- {hardware}, {machine['cpu_count']} cores",
        f"- {machine['platform']}",
        f"- Python {machine['python']}, mcp {machine['packages'].get('mcp')}, "
        f"torch {machine['packages'].get('torch')}",
        "",
        f"{payload['calls']} timed calls per configuration after {payload['warmup']} warm-up "
        f"calls, all to `{TOOL}`.",
        "",
        "## Latency",
        "",
        "| Configuration | Concurrency | p50 ms | p95 ms | p99 ms | mean ms | calls/s | errors |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in samples:
        lines.append(
            f"| {row['configuration']} | {row['concurrency']} | {row['p50_ms']} | "
            f"{row['p95_ms']} | {row['p99_ms']} | {row['mean_ms']} | "
            f"{row['throughput_per_second']} | {row['errors']} |"
        )

    lines += [
        "",
        "## Overhead over calling the upstream directly",
        "",
        "| Configuration @ concurrency | p50 added | p95 added | p99 added |",
        "| --- | --- | --- | --- |",
    ]
    for key, value in payload["overhead"].items():
        lines.append(
            f"| {key} | {value['p50_added_ms']} ms | {value['p95_added_ms']} ms | "
            f"{value['p99_added_ms']} ms |"
        )

    lines += [
        "",
        "## Reading these numbers",
        "",
        "- `direct` is the same upstream over the same transport with no gateway, so the",
        "  difference is the gateway and not the tool.",
        "- `auth+policy` runs authenticate, resolve, policy and forward. `full (rules)` adds",
        "  definition integrity, rate limiting, DLP, approval, the audit write-ahead, the output",
        "  size cap and the output scan - which is what ships by default.",
        "- Both `full` configurations write two audit rows per call, including the fsync-bound",
        "  write-ahead row. That is the single largest component of the overhead, and it is the",
        "  cost of being able to say afterwards what happened.",
        "- At concurrency 50 the numbers include queueing: each upstream has a concurrency cap,",
        "  so p99 there is a measure of the queue, not of per-call work.",
    ]
    return "\n".join(lines) + "\n"


def write_chart(payload: dict[str, Any], path: Path) -> Path | None:
    """A grouped bar chart of p50/p95/p99 per configuration. None if matplotlib is absent."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib is not installed; skipping the chart")
        return None

    sequential = [s for s in payload["samples"] if s["concurrency"] == 1]
    if not sequential:
        return None
    labels = [s["configuration"] for s in sequential]
    width = 0.26
    positions = range(len(labels))
    figure, axes = plt.subplots(figsize=(9, 5))
    for offset, key, name in (
        (-width, "p50_ms", "p50"),
        (0.0, "p95_ms", "p95"),
        (width, "p99_ms", "p99"),
    ):
        axes.bar(
            [p + offset for p in positions],
            [s[key] for s in sequential],
            width=width,
            label=name,
        )
    axes.set_xticks(list(positions))
    axes.set_xticklabels(labels, rotation=12, ha="right")
    axes.set_ylabel("latency (ms)")
    machine = payload["machine"]
    axes.set_title(
        f"mcp-warden latency per configuration, sequential\n"
        f"{machine.get('chip') or machine.get('processor')} · "
        f"{payload['calls']} calls to {TOOL}"
    )
    axes.legend()
    axes.grid(axis="y", alpha=0.3)
    figure.tight_layout()
    figure.savefig(path, dpi=140)
    plt.close(figure)
    return path


def write_report(
    samples: Sequence[Sample], *, directory: Path, calls: int, warmup: int
) -> tuple[Path, Path, Path | None]:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "machine": machine_info(),
        "tool": TOOL,
        "calls": calls,
        "warmup": warmup,
        "samples": [s.as_dict() for s in samples],
        "overhead": overhead(samples),
    }
    json_path = directory / f"bench-{stamp}.json"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    markdown_path = directory / f"bench-{stamp}.md"
    markdown_path.write_text(render_markdown(payload), encoding="utf-8")
    chart_path = write_chart(payload, directory / f"bench-{stamp}.png")
    return json_path, markdown_path, chart_path


# ----------------------------------------------------------------------------------------------


AUTH_POLICY_STAGES = ("authenticate", "resolve", "defaults", "policy", "forward")

#: Limits raised far above the shipped defaults for the duration of the benchmark.
#:
#: The rate-limit *stage still runs*, so its cost is measured - what changes is only the
#: capacity, so it does not refuse. Without this the benchmark measured the limiter working
#: correctly: a thousand calls as one caller spends the shipped per-tool bucket of 60 after the
#: first second, and every call after that came back denied in well under a millisecond. That
#: would have reported the full pipeline as *faster* than the cut-down one, which is the
#: opposite of the truth.
BENCH_LIMITS: dict[str, Any] = {
    "default": {
        "per_principal": {"capacity": 100000, "refill_per_second": 10000.0},
        "per_tool": {"capacity": 100000, "refill_per_second": 10000.0},
        "daily_calls": 1000000,
        "daily_destructive_calls": 1000000,
    },
    "roles": {},
    "max_result_bytes": 262144,
    "max_argument_bytes": 65536,
}


async def run_all(
    workdir: Path, *, calls: int, warmup: int, concurrencies: Sequence[int], with_ml: bool
) -> list[Sample]:
    """Measure every configuration at every concurrency, each on a fresh gateway.

    A gateway per measurement rather than per configuration: running three concurrency levels
    against one instance left sessions, pools and caches from the previous level in place, and
    the accumulated state eventually produced read timeouts. It also means a p50 measured
    sequentially is not quietly benefiting from a warmed-up pool that fifty concurrent clients
    filled a moment earlier.
    """
    samples: list[Sample] = []

    print("== direct upstream ==")
    for concurrency in concurrencies:
        run_dir = workdir / f"direct-c{concurrency}"
        run_dir.mkdir(parents=True, exist_ok=True)
        with direct_upstream(run_dir) as url:
            sample = await bench_direct(url, concurrency, calls, warmup)
        samples.append(sample)
        _print(sample)

    configurations: list[tuple[str, Sequence[str] | None, bool]] = [
        ("auth+policy", AUTH_POLICY_STAGES, False),
        ("full (rules)", None, False),
    ]
    if with_ml:
        configurations.append(("full (classifier)", None, True))

    for label, stages, classifier in configurations:
        print(f"== {label} ==")
        for concurrency in concurrencies:
            with gateway_for(
                workdir,
                label=f"{label}-c{concurrency}",
                stages=stages,
                classifier=classifier,
            ) as gateway:
                sample = await bench_gateway(
                    gateway,
                    label=label,
                    concurrency=concurrency,
                    calls=calls,
                    warmup=warmup,
                )
            samples.append(sample)
            _print(sample)
    return samples


def _print(sample: Sample) -> None:
    print(
        f"  c={sample.concurrency:<3} p50 {sample.p50:7.2f} ms  p95 {sample.p95:7.2f} ms  "
        f"p99 {sample.p99:7.2f} ms  {sample.throughput:7.1f} calls/s  "
        f"errors {sample.errors}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bench.latency", description="Measure what the gateway costs."
    )
    parser.add_argument("--calls", type=int, default=DEFAULT_CALLS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument(
        "--concurrency",
        type=int,
        nargs="*",
        default=list(CONCURRENCIES),
        help="One or more concurrency levels.",
    )
    parser.add_argument(
        "--no-ml",
        action="store_true",
        help="Skip the classifier configuration, which is what CI does.",
    )
    parser.add_argument("--results-dir", default=str(RESULTS_DIR))
    args = parser.parse_args(argv)

    configure_logging("WARNING")

    with_ml = not args.no_ml
    if with_ml:
        from redteam.runner import classifier_available

        from warden.config import ScanConfig

        model = ScanConfig().classifier_model
        if not classifier_available(model):
            print(f"classifier not available locally ({model}); skipping that configuration")
            with_ml = False

    import tempfile

    with tempfile.TemporaryDirectory(prefix="warden-bench-") as temp:
        samples = asyncio.run(
            run_all(
                Path(temp),
                calls=args.calls,
                warmup=args.warmup,
                concurrencies=args.concurrency,
                with_ml=with_ml,
            )
        )

    json_path, markdown_path, chart_path = write_report(
        samples, directory=Path(args.results_dir), calls=args.calls, warmup=args.warmup
    )
    print(f"\nwrote {json_path}\nwrote {markdown_path}")
    if chart_path:
        print(f"wrote {chart_path}")

    errors = sum(s.errors for s in samples)
    if errors:
        print(f"\nFAIL: {errors} calls errored during the benchmark", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
