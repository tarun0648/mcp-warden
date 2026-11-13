"""A sandboxed file MCP server: the second benign upstream.

Every path is resolved inside one sandbox root. Errors are short sentences, never stack traces,
because an error message is as much a disclosure channel as a successful read.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any, Final

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from servers.files.safe_path import PathNotAllowed, relative_to_root, safe_resolve

DEFAULT_SANDBOX_ROOT = "./sandbox"
MAX_FILE_BYTES: Final = 1024 * 1024
MAX_LISTING_ENTRIES: Final = 500


def sandbox_root() -> Path:
    return Path(os.environ.get("FILES_SANDBOX_ROOT", DEFAULT_SANDBOX_ROOT))


def build_server(root: Path | None = None) -> MCPServer:
    """Create the files server rooted at `root` (default: $FILES_SANDBOX_ROOT)."""
    base = (root if root is not None else sandbox_root()).resolve()
    base.mkdir(parents=True, exist_ok=True)

    server: MCPServer = MCPServer(
        name="files",
        version="0.1.0",
        instructions="Read and write text files inside one sandbox directory.",
    )

    @server.tool(description="List the entries of a directory inside the sandbox.")
    def list_files(
        path: Annotated[
            str, Field(max_length=512, description="Directory, relative to the sandbox root.")
        ] = ".",
    ) -> dict[str, Any]:
        try:
            target = safe_resolve(base, path)
        except PathNotAllowed as exc:
            raise ToolError(str(exc)) from exc
        if not target.exists():
            raise ToolError(f"no such directory: {path}")
        if not target.is_dir():
            raise ToolError(f"not a directory: {path}")
        entries: list[dict[str, Any]] = []
        for child in sorted(target.iterdir())[:MAX_LISTING_ENTRIES]:
            entries.append(
                {
                    "name": child.name,
                    "path": relative_to_root(base, child),
                    "kind": "dir" if child.is_dir() else "file",
                    "bytes": child.stat().st_size if child.is_file() else None,
                }
            )
        return {"path": relative_to_root(base, target), "entries": entries}

    @server.tool(description="Read a UTF-8 text file inside the sandbox. Maximum 1 MB.")
    def read_file(
        path: Annotated[str, Field(min_length=1, max_length=512, description="File to read.")],
    ) -> dict[str, Any]:
        try:
            target = safe_resolve(base, path)
        except PathNotAllowed as exc:
            raise ToolError(str(exc)) from exc
        if not target.exists():
            raise ToolError(f"no such file: {path}")
        if not target.is_file():
            raise ToolError(f"not a file: {path}")
        size = target.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ToolError(f"file is {size} bytes, over the 1 MB limit")
        try:
            content = target.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ToolError("file is not UTF-8 text") from exc
        return {"path": relative_to_root(base, target), "bytes": size, "content": content}

    @server.tool(
        description="Write a UTF-8 text file inside the sandbox, creating or replacing it."
    )
    def write_file(
        path: Annotated[str, Field(min_length=1, max_length=512, description="File to write.")],
        content: Annotated[str, Field(max_length=MAX_FILE_BYTES, description="Text to write.")],
    ) -> dict[str, Any]:
        try:
            target = safe_resolve(base, path)
        except PathNotAllowed as exc:
            raise ToolError(str(exc)) from exc
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_FILE_BYTES:
            raise ToolError(f"content is {len(encoded)} bytes, over the 1 MB limit")
        if target.is_dir():
            raise ToolError(f"not a file: {path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(encoded)
        return {"path": relative_to_root(base, target), "bytes": len(encoded)}

    @server.tool(description="Delete one file inside the sandbox. This cannot be undone.")
    def delete_file(
        path: Annotated[str, Field(min_length=1, max_length=512, description="File to delete.")],
    ) -> dict[str, Any]:
        try:
            target = safe_resolve(base, path)
        except PathNotAllowed as exc:
            raise ToolError(str(exc)) from exc
        if not target.exists():
            raise ToolError(f"no such file: {path}")
        if not target.is_file():
            raise ToolError(f"not a file: {path}")
        relative = relative_to_root(base, target)
        target.unlink()
        return {"deleted": relative}

    return server


__all__ = ["DEFAULT_SANDBOX_ROOT", "MAX_FILE_BYTES", "build_server", "sandbox_root"]
