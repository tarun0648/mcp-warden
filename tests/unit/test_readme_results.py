"""The README's results block is generated, never typed (hard rule 7)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bench.readme_results import END, START, TARGETS, apply, newest, render

pytestmark = pytest.mark.unit


def write(directory: Path, name: str, payload: dict) -> Path:  # type: ignore[type-arg]
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def redteam(blocked: int) -> dict:  # type: ignore[type-arg]
    run = {
        "label": "rules only",
        "attacks": 10,
        "blocked": blocked,
        "block_rate": blocked / 10,
        "benign": 4,
        "benign_allowed": 4,
        "false_positive_rate": 0.0,
        "categories": [{"attacks": 6}, {"attacks": 4}, {"attacks": 0}],
    }
    return {"runs": [run]}


def test_the_newest_file_wins(tmp_path: Path) -> None:
    write(tmp_path, "redteam-2026-01-01.json", redteam(1))
    write(tmp_path, "redteam-2026-02-01.json", redteam(9))
    assert newest(tmp_path, "redteam") == tmp_path / "redteam-2026-02-01.json"
    block = render(tmp_path)
    assert "9/10 (90.0%)" in block
    assert "1/10" not in block


def test_numbers_come_from_the_file_not_from_the_template(tmp_path: Path) -> None:
    write(tmp_path, "redteam-2026-01-01.json", redteam(7))
    assert "7/10 (70.0%)" in render(tmp_path)


def test_only_categories_with_attacks_are_counted(tmp_path: Path) -> None:
    write(tmp_path, "redteam-2026-01-01.json", redteam(10))
    assert "| 2 |" in render(tmp_path)


def test_an_empty_results_directory_says_so(tmp_path: Path) -> None:
    assert "No results yet" in render(tmp_path)


def test_rendering_is_deterministic(tmp_path: Path) -> None:
    """No clock in the block, or the up-to-date check below could never pass twice."""
    write(tmp_path, "redteam-2026-01-01.json", redteam(10))
    assert render(tmp_path) == render(tmp_path)


def test_apply_replaces_only_the_marked_block() -> None:
    text = f"before\n{START}\nold numbers\n{END}\nafter\n"
    updated = apply(text, f"{START}\nnew\n{END}")
    assert updated == f"before\n{START}\nnew\n{END}\nafter\n"


def test_a_file_without_markers_is_an_error_not_a_silent_no_op() -> None:
    with pytest.raises(ValueError):
        apply("no markers here", f"{START}\n{END}")


@pytest.mark.parametrize("target", TARGETS, ids=lambda p: p.name)
def test_the_committed_block_matches_the_committed_results(target: Path) -> None:
    """If this fails, someone edited the numbers by hand or forgot `make readme-results`."""
    assert target.is_file(), f"{target.name} is missing"
    text = target.read_text(encoding="utf-8")
    assert apply(text, render()) == text, f"{target.name} is stale: run `make readme-results`"
