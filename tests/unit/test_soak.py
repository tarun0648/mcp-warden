"""The soak test's arithmetic. The load itself runs under `make soak`, not in CI."""

from __future__ import annotations

import pytest
from bench.soak import MIN_SECONDS_FOR_SLOPE, MIX, Window, drift, slope_per_hour, totals

pytestmark = pytest.mark.unit


def window(
    index: int, *, rss: float | None, latencies: list[float], seconds: float = 60.0
) -> Window:
    return Window(
        index=index,
        started_s=index * seconds,
        calls=len(latencies),
        latencies_ms=list(latencies),
        rss_mb=rss,
    )


def test_slope_of_a_flat_line_is_zero() -> None:
    assert slope_per_hour([(0, 100.0), (600, 100.0), (1200, 100.0)]) == pytest.approx(0.0)


def test_slope_is_expressed_per_hour() -> None:
    # +1 MiB every 60 s is +60 MiB per hour.
    points = [(i * 60.0, 100.0 + i) for i in range(30)]
    assert slope_per_hour(points) == pytest.approx(60.0)


def test_slope_needs_two_distinct_points() -> None:
    assert slope_per_hour([(0, 1.0)]) is None
    assert slope_per_hour([(5, 1.0), (5, 2.0)]) is None


def test_the_first_window_is_excluded_as_warm_up() -> None:
    """Comparing against warm-up would report the warm-up as an improvement."""
    windows = [window(0, rss=500.0, latencies=[100.0] * 10)] + [
        window(i, rss=200.0, latencies=[10.0] * 10) for i in range(1, 12)
    ]
    result = drift(windows)
    assert result["rss_start_mb"] == 200.0
    assert result["p95_start_ms"] == 10.0


def test_a_leak_shows_as_growth_and_a_positive_slope() -> None:
    windows = [window(i, rss=200.0 + 2 * i, latencies=[10.0] * 10) for i in range(30)]
    result = drift(windows)
    assert result["rss_change_mb"] > 0
    assert result["rss_slope_mb_per_hour"] == pytest.approx(120.0)


def test_a_short_run_reports_no_slope_rather_than_an_extrapolation() -> None:
    """45 s of samples turned into "MiB per hour" is noise multiplied by eighty."""
    windows = [window(i, rss=300.0 - 20 * i, latencies=[10.0] * 5, seconds=10.0) for i in range(5)]
    result = drift(windows)
    assert result["rss_seconds_covered"] < MIN_SECONDS_FOR_SLOPE
    assert result["rss_slope_mb_per_hour"] is None


def test_latency_drift_compares_pooled_percentiles() -> None:
    windows = [window(0, rss=1.0, latencies=[1.0])] + [
        window(i, rss=1.0, latencies=[10.0] * 100 if i <= 5 else [20.0] * 100) for i in range(1, 12)
    ]
    result = drift(windows)
    assert result["p95_start_ms"] == 10.0
    assert result["p95_end_ms"] == 20.0
    assert result["p95_change_pct"] == pytest.approx(100.0)


def test_too_few_windows_says_so() -> None:
    assert drift([window(0, rss=1.0, latencies=[1.0])]) == {"enough_data": False}


def test_totals_pool_every_window_and_count_outcomes() -> None:
    first = window(0, rss=1.0, latencies=[1.0, 2.0])
    first.outcomes = {"a:allowed": 2}
    second = window(1, rss=1.0, latencies=[3.0])
    second.errors = 1
    second.outcomes = {"a:allowed": 1}
    result = totals([first, second])
    assert result["calls"] == 3
    assert result["errors"] == 1
    assert result["outcomes"] == {"a:allowed": 3}
    assert result["max_ms"] == 3.0


def test_the_mix_exercises_the_denial_path() -> None:
    """A soak of only allowed calls would never exercise the audit write for a denial."""
    expectations = [expected for _tool, _args, expected in MIX]
    assert "denied" in expectations
    assert expectations.count("allowed") >= len(MIX) // 2


def test_second_half_slope_ignores_a_warm_up_step() -> None:
    """Step up, then flat: the whole-run line slopes, the second half does not."""
    from bench.soak import second_half_slope

    rows = [{"minute": float(m), "rss_mb": 200.0 if m < 9 else 250.0} for m in range(30)]
    whole = slope_per_hour([(r["minute"] * 60, r["rss_mb"]) for r in rows])
    assert whole is not None and whole > 50
    assert second_half_slope(rows)["rss_slope_second_half_mb_per_hour"] == pytest.approx(0.0)


def test_second_half_slope_still_sees_a_real_leak() -> None:
    from bench.soak import second_half_slope

    rows = [{"minute": float(m), "rss_mb": 200.0 + m} for m in range(30)]
    assert second_half_slope(rows)["rss_slope_second_half_mb_per_hour"] == pytest.approx(60.0)


def test_second_half_slope_needs_enough_time() -> None:
    from bench.soak import second_half_slope

    rows = [{"minute": m / 6, "rss_mb": 200.0 + m} for m in range(8)]
    assert second_half_slope(rows)["rss_slope_second_half_mb_per_hour"] is None
