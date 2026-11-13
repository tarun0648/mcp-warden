"""Run the files server over stdio, or over Streamable HTTP with --http PORT."""

from __future__ import annotations

import argparse

from servers.files import build_server


def main() -> None:
    parser = argparse.ArgumentParser(prog="servers.files", description=__doc__)
    parser.add_argument(
        "--http", type=int, default=None, metavar="PORT", help="serve Streamable HTTP on PORT"
    )
    parser.add_argument("--host", default="127.0.0.1", help="host to bind when serving HTTP")
    args = parser.parse_args()

    server = build_server()
    if args.http is None:
        server.run("stdio")
    else:
        server.run("streamable-http", host=args.host, port=args.http)


if __name__ == "__main__":
    main()
