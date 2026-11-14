"""No invisible or direction-changing characters in the repository's own text files.

This project's premise is that a character a human cannot see is an attack surface: the
definition scanner flags them in tool descriptions, and the agent strips them before a model
reads anything. The same applies to the code that implements those checks. A literal U+202E in
a source file is exactly the "trojan source" problem (CVE-2021-42574): a reviewer sees one
thing and the interpreter runs another. Bandit's B613 found two; a scan of the whole tree found 34 lines of Python and one data file.

Where the code or a test needs such a character, it writes it as an escape (`"\\u202e"`), which
means the same thing to Python, JSON and YAML and is visible to whoever reads the diff.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKED_DIRS = (
    "src",
    "servers",
    "agent",
    "redteam",
    "bench",
    "tests",
    "config",
    "migrations",
    "deploy",
)
CHECKED_SUFFIXES = {".py", ".yaml", ".yml", ".json", ".jsonl", ".html", ".css", ".toml", ".ini"}
SKIPPED_PARTS = {"__pycache__", ".venv", "node_modules"}


def text_files() -> list[Path]:
    files = []
    for directory in CHECKED_DIRS:
        for path in (REPO_ROOT / directory).rglob("*"):
            if (
                path.is_file()
                and path.suffix in CHECKED_SUFFIXES
                and not SKIPPED_PARTS & set(path.parts)
            ):
                files.append(path)
    for name in ("pyproject.toml", "Makefile", "docker-compose.yml", "alembic.ini", "Dockerfile"):
        if (REPO_ROOT / name).is_file():
            files.append(REPO_ROOT / name)
    return files


def test_the_check_actually_looks_at_files() -> None:
    """Guard against the test passing because it found nothing to check."""
    names = {p.name for p in text_files()}
    assert "text_rules.py" in names
    assert "payloads.py" in names
    assert len(names) > 100


def test_no_text_file_contains_a_literal_format_character() -> None:
    offenders = []
    for path in text_files():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            found = [f"U+{ord(c):04X}" for c in line if unicodedata.category(c) == "Cf"]
            if found:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}: {' '.join(found)}")
    assert not offenders, "write these as \\u escapes:\n" + "\n".join(offenders)


def test_the_escaped_characters_still_mean_what_they_did() -> None:
    """Escaping must not have turned a detector's character set into a set of backslashes."""
    from servers.evil.payloads import RIGHT_TO_LEFT_OVERRIDE, ZERO_WIDTH_SPACE

    from warden.scan.text_rules import BIDI_CONTROLS

    assert chr(0x202E) == RIGHT_TO_LEFT_OVERRIDE
    assert chr(0x200B) == ZERO_WIDTH_SPACE
    assert chr(0x202E) in BIDI_CONTROLS
    assert all(len(c) == 1 and unicodedata.category(c) == "Cf" for c in BIDI_CONTROLS)
