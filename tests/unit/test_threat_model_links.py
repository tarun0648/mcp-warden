"""Every test the threat model cites must exist.

A threat model that names `test_foo` as the proof of a mitigation is only worth something while
`test_foo` exists and still says what it says. Renaming or deleting a test without updating the
document would leave a claim with no evidence behind it; this makes that a test failure.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS = [
    REPO_ROOT / "docs" / "threat-model.md",
    REPO_ROOT / "docs" / "clients.md",
    REPO_ROOT / "README.md",
]
REFERENCE = re.compile(r"(tests/[\w/]+\.py)::(test_\w+)")


def references() -> list[tuple[Path, str, str]]:
    found = []
    for doc in DOCS:
        if doc.is_file():
            for path, name in REFERENCE.findall(doc.read_text(encoding="utf-8")):
                found.append((doc, path, name))
    return found


def test_the_threat_model_cites_tests_at_all() -> None:
    cited = [r for r in references() if r[0].name == "threat-model.md"]
    assert len(cited) >= 80, f"only {len(cited)} citations; the STRIDE tables need their proofs"


@pytest.mark.parametrize(("doc", "path", "name"), references(), ids=lambda v: str(v))
def test_every_cited_test_exists(doc: Path, path: str, name: str) -> None:
    source = REPO_ROOT / path
    assert source.is_file(), f"{doc.name} cites {path}, which does not exist"
    text = source.read_text(encoding="utf-8")
    assert re.search(rf"^(async )?def {name}\(", text, re.M), (
        f"{doc.name} cites {path}::{name}, which is not defined there"
    )


def test_every_stride_row_names_a_proof() -> None:
    """A mitigation with an empty proof column is a claim, not a control."""
    text = (REPO_ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    rows = [line for line in text.splitlines() if re.match(r"^\| [STRIDE] \|", line)]
    assert len(rows) >= 60
    for row in rows:
        proof = row.rstrip(" |").rsplit(" | ", 1)[-1]
        assert (
            REFERENCE.search(proof)
            or "reviewed" in proof
            or "make security" in proof
            or "verified by running" in proof
        ), row
