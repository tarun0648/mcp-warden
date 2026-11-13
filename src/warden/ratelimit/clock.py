"""A clock behind an interface, so tests can move time instead of sleeping.

Rate limits and daily budgets are the two places where "wait a while" would otherwise be the
only way to test the interesting behaviour. Every time-dependent decision in this package reads
the clock that was injected into it.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Wall-clock time, in UTC."""

    def now(self) -> float:
        """Seconds since the Unix epoch."""
        ...

    def utcnow(self) -> datetime:
        """The current time as a timezone-aware UTC datetime."""
        ...


class SystemClock:
    """The real clock."""

    def now(self) -> float:
        return time.time()

    def utcnow(self) -> datetime:
        return datetime.now(UTC)


class FakeClock:
    """A clock tests move by hand."""

    def __init__(self, start: float | datetime | None = None) -> None:
        if isinstance(start, datetime):
            self._now = start.timestamp()
        elif start is None:
            self._now = datetime(2026, 11, 13, 12, 0, 0, tzinfo=UTC).timestamp()
        else:
            self._now = float(start)

    def now(self) -> float:
        return self._now

    def utcnow(self) -> datetime:
        return datetime.fromtimestamp(self._now, UTC)

    def advance(self, seconds: float) -> None:
        self._now += seconds

    def set(self, moment: datetime) -> None:
        self._now = moment.timestamp()


def utc_day_key(moment: datetime) -> str:
    """The bucket a daily budget counts into: `YYYYMMDD` in UTC."""
    return moment.astimezone(UTC).strftime("%Y%m%d")


def seconds_until_next_utc_midnight(moment: datetime) -> int:
    """How long the current day's budget counter should live, at least one second."""
    current = moment.astimezone(UTC)
    tomorrow = (current + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(int((tomorrow - current).total_seconds()), 1)


__all__ = [
    "Clock",
    "FakeClock",
    "SystemClock",
    "seconds_until_next_utc_midnight",
    "utc_day_key",
]
