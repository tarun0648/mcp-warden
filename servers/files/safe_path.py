"""Resolve a client-supplied path inside a sandbox root, or refuse it.

Everything hangs off one rule: the *real* path (symlinks followed) must be the root itself or
live under it. The checks before that exist to make refusals clear and to stop tricks that
would otherwise resolve to something legal-looking.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Final

MAX_PATH_LENGTH: Final = 512
#: Any percent-encoded byte. We refuse these rather than decoding them: decoding is what turns
#: "%2e%2e/x" into traversal, and a literal '%' in a filename is rare enough to live without.
PERCENT_ENCODING_RE: Final = re.compile(r"%[0-9A-Fa-f]{2}")


class PathNotAllowed(ValueError):
    """The requested path is outside the sandbox or otherwise unsafe."""


def safe_resolve(root: Path, candidate: str) -> Path:
    """Return the absolute path `candidate` names inside `root`, or raise `PathNotAllowed`.

    The returned path may not exist yet (so it works for writes); its *parent* chain is what
    gets resolved, so a symlink anywhere along the way cannot escape.
    """
    if not isinstance(candidate, str):  # pragma: no cover - the schema already enforces this
        raise PathNotAllowed("path must be a string")
    if candidate == "":
        raise PathNotAllowed("path must not be empty")
    if "\x00" in candidate:
        raise PathNotAllowed("path contains a NUL byte")
    if len(candidate) > MAX_PATH_LENGTH:
        raise PathNotAllowed(f"path longer than {MAX_PATH_LENGTH} characters")
    if PERCENT_ENCODING_RE.search(candidate):
        raise PathNotAllowed("path contains percent-encoding, which is not accepted here")
    if candidate.startswith(("/", "\\")) or (len(candidate) > 1 and candidate[1] == ":"):
        raise PathNotAllowed("path must be relative to the sandbox root")

    parts = [part for part in re.split(r"[/\\]+", candidate) if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise PathNotAllowed("path must not contain '..'")

    real_root = Path(os.path.realpath(root))
    target = real_root.joinpath(*parts) if parts else real_root

    # Resolve the deepest existing ancestor and re-append the rest, so a symlinked directory in
    # the middle of the path is followed and checked even when the leaf does not exist yet.
    existing = target
    tail: list[str] = []
    while not existing.exists() and existing != real_root:
        tail.append(existing.name)
        existing = existing.parent
    resolved_existing = Path(os.path.realpath(existing))
    resolved = resolved_existing.joinpath(*reversed(tail))

    if resolved != real_root and real_root not in resolved.parents:
        raise PathNotAllowed("path resolves outside the sandbox root")
    return resolved


def relative_to_root(root: Path, resolved: Path) -> str:
    """Render a resolved path the way the client supplied it, for echoing back."""
    real_root = Path(os.path.realpath(root))
    if resolved == real_root:
        return "."
    return str(resolved.relative_to(real_root))
