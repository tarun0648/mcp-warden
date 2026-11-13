"""files exercised through a real MCP client session, with the traversal matrix."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from servers.files.safe_path import PathNotAllowed, safe_resolve

from tests.helpers import error_text, files_client, payload

pytestmark = pytest.mark.integration


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "sandbox"
    (root / "sub").mkdir(parents=True)
    (root / "hello.txt").write_text("hello world\n", encoding="utf-8")
    (root / "sub" / "nested.txt").write_text("nested\n", encoding="utf-8")
    # A secret that lives outside the sandbox: nothing the server does may reveal it.
    (tmp_path / "outside.txt").write_text("OUTSIDE-SECRET\n", encoding="utf-8")
    return root


async def test_tools_list(sandbox: Path) -> None:
    async with files_client(sandbox) as client:
        listing = await client.list_tools()
    assert {tool.name for tool in listing.tools} == {
        "list_files",
        "read_file",
        "write_file",
        "delete_file",
    }


async def test_list_read_write_delete_round_trip(sandbox: Path) -> None:
    async with files_client(sandbox) as client:
        listed = payload(await client.call_tool("list_files", {"path": "."}))
        assert {entry["name"] for entry in listed["entries"]} == {"hello.txt", "sub"}

        read = payload(await client.call_tool("read_file", {"path": "hello.txt"}))
        assert read["content"] == "hello world\n"

        written = payload(
            await client.call_tool("write_file", {"path": "sub/new.txt", "content": "fresh"})
        )
        assert written["path"] == "sub/new.txt"
        assert (
            payload(await client.call_tool("read_file", {"path": "sub/new.txt"}))["content"]
            == "fresh"
        )

        deleted = payload(await client.call_tool("delete_file", {"path": "sub/new.txt"}))
        assert deleted["deleted"] == "sub/new.txt"
        assert (await client.call_tool("read_file", {"path": "sub/new.txt"})).is_error


async def test_write_creates_missing_directories_inside_the_sandbox(sandbox: Path) -> None:
    async with files_client(sandbox) as client:
        payload(await client.call_tool("write_file", {"path": "a/b/c.txt", "content": "x"}))
    assert (sandbox / "a" / "b" / "c.txt").read_text() == "x"


TRAVERSAL_CASES = [
    "../outside.txt",
    "../../etc/passwd",
    "/etc/passwd",
    "sub/../../outside.txt",
    "%2e%2e/outside.txt",
    "%2E%2E%2Foutside.txt",
    "sub/%2e%2e/%2e%2e/outside.txt",
    "..",
    "./../outside.txt",
    "sub/../..",
    "\\..\\outside.txt",
    "/",
]


@pytest.mark.parametrize("path", TRAVERSAL_CASES)
async def test_traversal_attempts_are_rejected(sandbox: Path, path: str) -> None:
    async with files_client(sandbox) as client:
        for tool, args in (
            ("read_file", {"path": path}),
            ("list_files", {"path": path}),
            ("delete_file", {"path": path}),
            ("write_file", {"path": path, "content": "pwned"}),
        ):
            result = await client.call_tool(tool, args)
            assert result.is_error, f"{tool} accepted {path!r}"
            error_text(result)
    assert (sandbox.parent / "outside.txt").read_text() == "OUTSIDE-SECRET\n"


async def test_nul_byte_in_path_is_rejected(sandbox: Path) -> None:
    async with files_client(sandbox) as client:
        result = await client.call_tool("read_file", {"path": "hello.txt\x00.png"})
    assert "NUL" in error_text(result)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
async def test_symlink_escaping_the_sandbox_is_rejected(sandbox: Path) -> None:
    (sandbox / "escape").symlink_to(sandbox.parent / "outside.txt")
    async with files_client(sandbox) as client:
        result = await client.call_tool("read_file", {"path": "escape"})
    assert "outside the sandbox root" in error_text(result)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
async def test_symlinked_directory_escaping_the_sandbox_is_rejected(sandbox: Path) -> None:
    """The check follows symlinks in the middle of a path, not just at the leaf."""
    (sandbox / "jump").symlink_to(sandbox.parent, target_is_directory=True)
    async with files_client(sandbox) as client:
        result = await client.call_tool("read_file", {"path": "jump/outside.txt"})
    assert "outside the sandbox root" in error_text(result)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
async def test_symlink_that_stays_inside_the_sandbox_still_works(sandbox: Path) -> None:
    """No false positive: a symlink pointing within the sandbox is fine."""
    (sandbox / "alias.txt").symlink_to(sandbox / "hello.txt")
    async with files_client(sandbox) as client:
        result = await client.call_tool("read_file", {"path": "alias.txt"})
    assert payload(result)["content"] == "hello world\n"


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
async def test_write_through_an_escaping_symlink_is_rejected(sandbox: Path) -> None:
    (sandbox / "jump").symlink_to(sandbox.parent, target_is_directory=True)
    async with files_client(sandbox) as client:
        result = await client.call_tool(
            "write_file", {"path": "jump/implanted.txt", "content": "pwned"}
        )
    assert result.is_error
    assert not (sandbox.parent / "implanted.txt").exists()


async def test_read_rejects_a_file_over_one_megabyte(sandbox: Path) -> None:
    (sandbox / "big.txt").write_bytes(b"a" * (1024 * 1024 + 1))
    async with files_client(sandbox) as client:
        result = await client.call_tool("read_file", {"path": "big.txt"})
    assert "over the 1 MB limit" in error_text(result)


async def test_read_rejects_non_utf8_content(sandbox: Path) -> None:
    (sandbox / "binary.bin").write_bytes(b"\xff\xfe\x00\x01")
    async with files_client(sandbox) as client:
        result = await client.call_tool("read_file", {"path": "binary.bin"})
    assert "not UTF-8 text" in error_text(result)


async def test_missing_file_gives_a_clean_error(sandbox: Path) -> None:
    async with files_client(sandbox) as client:
        result = await client.call_tool("read_file", {"path": "nope.txt"})
    assert "no such file" in error_text(result)


async def test_reading_a_directory_is_an_error(sandbox: Path) -> None:
    async with files_client(sandbox) as client:
        result = await client.call_tool("read_file", {"path": "sub"})
    assert "not a file" in error_text(result)


async def test_listing_a_file_is_an_error(sandbox: Path) -> None:
    async with files_client(sandbox) as client:
        result = await client.call_tool("list_files", {"path": "hello.txt"})
    assert "not a directory" in error_text(result)


def test_safe_resolve_allows_the_root_itself(sandbox: Path) -> None:
    assert safe_resolve(sandbox, ".") == Path(os.path.realpath(sandbox))


@pytest.mark.parametrize("path", ["", "a" * 600])
def test_safe_resolve_rejects_degenerate_paths(sandbox: Path, path: str) -> None:
    with pytest.raises(PathNotAllowed):
        safe_resolve(sandbox, path)
