"""Both upstream servers must answer tools/list over stdio and over Streamable HTTP.

The gateway reaches upstreams over exactly these two transports, so these tests cover the
entrypoints (`python -m servers.<name>`) rather than the in-process shortcut the other tests use.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

import httpx
import pytest
from mcp import Client, StdioServerParameters

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_TOOLS = {
    "notes_db": {"list_notes", "search_notes", "get_note", "create_note", "delete_note", "run_sql"},
    "files": {"list_files", "read_file", "write_file", "delete_file"},
}


def free_port() -> int:
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def server_env(tmp_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["NOTES_DB_PATH"] = str(tmp_path / "notes.sqlite3")
    env["FILES_SANDBOX_ROOT"] = str(tmp_path / "sandbox")
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


@contextmanager
def http_server(module: str, port: int, env: dict[str, str]) -> Iterator[None]:
    """Run `python -m servers.<module> --http PORT` until the context exits."""
    process = subprocess.Popen(
        [sys.executable, "-m", f"servers.{module}", "--http", str(port)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                _, stderr = process.communicate()
                raise AssertionError(f"{module} exited early: {stderr.decode()[-2000:]}")
            try:
                # Any HTTP answer means the socket is serving; MCP needs POST, so a 4xx is fine.
                httpx.get(f"http://127.0.0.1:{port}/mcp", timeout=0.5)
                break
            except httpx.HTTPError:
                time.sleep(0.2)
        else:
            raise AssertionError(f"{module} did not start listening on {port}")
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            process.kill()


@pytest.mark.parametrize("module", ["notes_db", "files"])
async def test_tools_list_over_stdio(tmp_path: Path, module: str) -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", f"servers.{module}"],
        cwd=str(REPO_ROOT),
        env=server_env(tmp_path),
    )
    async with Client(params) as client:
        listing = await client.list_tools()
    assert {tool.name for tool in listing.tools} == EXPECTED_TOOLS[module]


@pytest.mark.parametrize("module", ["notes_db", "files"])
async def test_tools_list_over_streamable_http(tmp_path: Path, module: str) -> None:
    port = free_port()
    with http_server(module, port, server_env(tmp_path)):
        async with Client(f"http://127.0.0.1:{port}/mcp") as client:
            listing = await client.list_tools()
            assert {tool.name for tool in listing.tools} == EXPECTED_TOOLS[module]
            if module == "files":
                result = await client.call_tool("list_files", {"path": "."})
                assert not result.is_error
