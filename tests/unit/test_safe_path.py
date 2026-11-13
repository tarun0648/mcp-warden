"""Unit tests for sandbox path resolution."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from servers.files.safe_path import PathNotAllowed, relative_to_root, safe_resolve

pytestmark = pytest.mark.unit


@pytest.fixture
def root(tmp_path: Path) -> Path:
    base = tmp_path / "root"
    (base / "sub").mkdir(parents=True)
    return base


@pytest.mark.parametrize(
    ("given_path", "expected"),
    [
        (".", ""),
        ("sub", "sub"),
        ("sub/", "sub"),
        ("./sub", "sub"),
        ("sub/./file.txt", "sub/file.txt"),
        ("sub//file.txt", "sub/file.txt"),
        ("new/deep/file.txt", "new/deep/file.txt"),
    ],
)
def test_accepts_paths_inside_the_root(root: Path, given_path: str, expected: str) -> None:
    resolved = safe_resolve(root, given_path)
    real_root = Path(os.path.realpath(root))
    assert resolved == (real_root / expected if expected else real_root)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "..",
        "../x",
        "sub/../../x",
        "/etc/passwd",
        "\\windows\\system32",
        "%2e%2e/x",
        "a\x00b",
        "x" * 600,
        "C:\\Windows",
    ],
)
def test_rejects_unsafe_paths(root: Path, bad: str) -> None:
    with pytest.raises(PathNotAllowed):
        safe_resolve(root, bad)


def test_relative_to_root_round_trip(root: Path) -> None:
    assert relative_to_root(root, safe_resolve(root, "sub")) == "sub"
    assert relative_to_root(root, safe_resolve(root, ".")) == "."


@given(st.text(max_size=120))
def test_resolution_either_stays_inside_or_refuses(
    tmp_path_factory: pytest.TempPathFactory, candidate: str
) -> None:
    base = tmp_path_factory.mktemp("fuzz")
    real_root = Path(os.path.realpath(base))
    try:
        resolved = safe_resolve(base, candidate)
    except PathNotAllowed:
        return
    assert resolved == real_root or real_root in resolved.parents
