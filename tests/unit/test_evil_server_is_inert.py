"""The malicious server must be text and sleeps only.

This scans the package's own source with the AST, not a substring grep, so a rename or an alias
cannot hide a dangerous call. It is the test that lets a reviewer trust the rest of the red-team
suite: the "attacker" in these tests cannot actually do anything.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

EVIL_PACKAGE = Path(__file__).resolve().parents[2] / "servers" / "evil"

#: Modules the behaviour code must not import at all.
FORBIDDEN_MODULES = {
    "subprocess",
    "socket",
    "socketserver",
    "requests",
    "httpx",
    "httpx2",
    "urllib",
    "urllib.request",
    "shutil",
    "ctypes",
    "pickle",
    "multiprocessing",
    "tempfile",
    "glob",
    "sqlite3",
    "webbrowser",
    "smtplib",
    "ftplib",
    "telnetlib",
}

#: Dotted calls that would reach the machine even from an allowed module.
FORBIDDEN_ATTRIBUTES = {
    ("os", "remove"),
    ("os", "unlink"),
    ("os", "rmdir"),
    ("os", "removedirs"),
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "spawnv"),
    ("os", "fork"),
    ("os", "kill"),
    ("os", "rename"),
    ("os", "mkdir"),
    ("os", "makedirs"),
    ("os", "chmod"),
    ("os", "open"),
    ("os", "write"),
    ("os", "truncate"),
    ("os", "walk"),
    ("sys", "exit"),
}

#: Builtins that read or write the outside world.
FORBIDDEN_BUILTINS = {"open", "eval", "exec", "compile", "__import__", "input", "breakpoint"}

#: Only the entrypoint may import a server runtime, because serving is its whole job.
BEHAVIOUR_FILES = ["__init__.py", "payloads.py"]
ENTRYPOINT_ALLOWED_IMPORTS = {"argparse", "asyncio", "uvicorn", "mcp.server.stdio", "servers.evil"}


def _module_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


@pytest.mark.parametrize("filename", BEHAVIOUR_FILES)
def test_no_forbidden_imports(filename: str) -> None:
    modules = _module_names(_parse(EVIL_PACKAGE / filename))
    roots = {name.split(".")[0] for name in modules} | modules
    offending = roots & FORBIDDEN_MODULES
    assert not offending, f"{filename} imports {sorted(offending)}"


@pytest.mark.parametrize("filename", BEHAVIOUR_FILES)
def test_no_forbidden_attribute_calls(filename: str) -> None:
    tree = _parse(EVIL_PACKAGE / filename)
    found: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and (node.value.id, node.attr) in FORBIDDEN_ATTRIBUTES
        ):
            found.append(f"{node.value.id}.{node.attr}")
    assert not found, f"{filename} calls {sorted(set(found))}"


@pytest.mark.parametrize("filename", BEHAVIOUR_FILES)
def test_no_forbidden_builtins(filename: str) -> None:
    tree = _parse(EVIL_PACKAGE / filename)
    found = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in FORBIDDEN_BUILTINS
    }
    assert not found, f"{filename} calls {sorted(found)}"


def test_entrypoint_imports_only_what_serving_needs() -> None:
    """__main__ does bind a socket, by design; nothing else may creep in with it."""
    modules = _module_names(_parse(EVIL_PACKAGE / "__main__.py"))
    unexpected = modules - ENTRYPOINT_ALLOWED_IMPORTS - {"__future__"}
    assert not unexpected, f"__main__.py imports {sorted(unexpected)}"


def test_every_source_file_is_covered_by_this_scan() -> None:
    """A new module in the package must be added to BEHAVIOUR_FILES deliberately."""
    on_disk = {path.name for path in EVIL_PACKAGE.glob("*.py")}
    assert on_disk == set(BEHAVIOUR_FILES) | {"__main__.py"}, (
        "servers/evil gained or lost a module; extend this scan before shipping it"
    )
