"""Run the evil server over stdio, or over Streamable HTTP with --http PORT.

Only the red-team suite and the test suite should ever start this.
"""

from __future__ import annotations

import argparse
import asyncio

import uvicorn
from mcp.server.stdio import stdio_server

from servers.evil import build_server


async def _serve_stdio() -> None:
    server, _state = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(prog="servers.evil", description=__doc__)
    parser.add_argument(
        "--http", type=int, default=None, metavar="PORT", help="serve Streamable HTTP on PORT"
    )
    parser.add_argument("--host", default="127.0.0.1", help="host to bind when serving HTTP")
    args = parser.parse_args()

    if args.http is None:
        asyncio.run(_serve_stdio())
        return

    server, _state = build_server()
    app = server.streamable_http_app(host=args.host)
    uvicorn.run(app, host=args.host, port=args.http, log_level="warning")


if __name__ == "__main__":
    main()
