"""Request-size and request-shape limits, enforced before any handler reads the body.

Two problems, both found by reading the MCP SDK rather than assumed:

* **The SDK buffers the whole body.** `StreamableHTTPServerTransport` calls
  `await request.body()` with no cap, so an authenticated caller could make the gateway hold
  an arbitrarily large request in memory before a single stage runs. `max_argument_bytes`
  is checked much later, after parsing. This middleware refuses an oversized body with 413:
  up front when `Content-Length` says so, and while streaming when it does not (chunked
  encoding has no length to check), so neither path buffers more than the limit.

* **JSON-RPC batches.** Batching was removed from MCP in protocol revision 2025-06-18, and the
  gateway targets 2026-07-28. The SDK happens to reject an array body today because its
  message adapter does not accept one, but a security property should not depend on a
  third-party validator's incidental behaviour. The gateway's batch size limit is therefore
  zero, and it is enforced here, by the gateway, with a proper JSON-RPC error. A batch would
  also be a way to put many tool calls behind one HTTP request, which is exactly what the
  per-request audit and rate-limit accounting assume cannot happen.

Pure ASGI rather than Starlette's `BaseHTTPMiddleware`, because the latter buffers responses
and breaks the SSE streams the MCP transport uses.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, Final

from warden.logging import get_logger

logger = get_logger(__name__)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

#: JSON-RPC 2.0 "Invalid Request".
INVALID_REQUEST: Final = -32600
#: Methods that carry a body worth limiting.
BODY_METHODS: Final = frozenset({"POST", "PUT", "PATCH"})


class BodyTooLarge(Exception):
    """Raised inside `receive` once the streamed body passes the limit."""


class RequestLimitsMiddleware:
    """413 for an oversized body; a JSON-RPC error for a batch sent to the MCP endpoint."""

    def __init__(self, app: ASGIApp, *, max_body_bytes: int, mcp_path: str = "/mcp") -> None:
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.mcp_path = mcp_path.rstrip("/") or "/"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method", "GET") not in BODY_METHODS:
            await self.app(scope, receive, send)
            return

        declared = _content_length(scope)
        if declared is not None and declared > self.max_body_bytes:
            _log_refusal(scope, "declared", declared, self.max_body_bytes)
            await _too_large(send, self.max_body_bytes)
            return

        if self._is_mcp(scope):
            # Read the whole body here - bounded by the limit - so the batch check can look at
            # it, then replay it to the transport. Bounded buffering is the point: the SDK
            # would otherwise buffer an unbounded one.
            try:
                body = await _read_bounded(receive, self.max_body_bytes)
            except BodyTooLarge:
                _log_refusal(scope, "streamed", None, self.max_body_bytes)
                await _too_large(send, self.max_body_bytes)
                return
            if _is_batch(body):
                logger.warning(
                    "refused a JSON-RPC batch",
                    extra={"warden": {"path": scope.get("path"), "bytes": len(body)}},
                )
                await _batch_refused(send)
                return
            await self.app(scope, _replay(body, receive), send)
            return

        # Everything else streams through a counting `receive`, so a form post to the approval
        # UI or an admin API call is held to the same limit without being buffered here.
        started = False

        async def send_tracking(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, _counting(receive, self.max_body_bytes), send_tracking)
        except BodyTooLarge:
            _log_refusal(scope, "streamed", None, self.max_body_bytes)
            if not started:
                await _too_large(send, self.max_body_bytes)

    def _is_mcp(self, scope: Scope) -> bool:
        path = str(scope.get("path", "")).rstrip("/") or "/"
        return path == self.mcp_path


def _content_length(scope: Scope) -> int | None:
    for key, value in scope.get("headers", []):
        if bytes(key).lower() == b"content-length":
            try:
                length = int(bytes(value).decode("latin-1").strip())
            except ValueError:
                return None
            return length if length >= 0 else None
    return None


async def _read_bounded(receive: Receive, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = bytes(message.get("body", b""))
        total += len(chunk)
        if total > limit:
            raise BodyTooLarge
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _replay(body: bytes, receive: Receive) -> Receive:
    """A `receive` that yields the already-read body once, then defers to the real one."""
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


def _counting(receive: Receive, limit: int) -> Receive:
    total = 0

    async def counting() -> Message:
        nonlocal total
        message = await receive()
        if message["type"] == "http.request":
            total += len(message.get("body", b""))
            if total > limit:
                raise BodyTooLarge
        return message

    return counting


def _is_batch(body: bytes) -> bool:
    """True when the body is a JSON array. Malformed JSON is left for the transport to refuse."""
    stripped = body.lstrip(b" \t\r\n\xef\xbb\xbf")
    return stripped.startswith(b"[")


async def _too_large(send: Send, limit: int) -> None:
    payload = json.dumps(
        {
            "error": "payload_too_large",
            "error_description": f"request body exceeds {limit} bytes",
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


async def _batch_refused(send: Send) -> None:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": INVALID_REQUEST,
                "message": (
                    "JSON-RPC batches are not accepted: batching was removed from MCP in "
                    "protocol revision 2025-06-18. Send one request per HTTP POST."
                ),
            },
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 400,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def _log_refusal(scope: Scope, how: str, declared: int | None, limit: int) -> None:
    logger.warning(
        "refused an oversized request body",
        extra={
            "warden": {
                "path": scope.get("path"),
                "method": scope.get("method"),
                "how": how,
                "declared_bytes": declared,
                "limit_bytes": limit,
            }
        },
    )


__all__ = ["INVALID_REQUEST", "BodyTooLarge", "RequestLimitsMiddleware"]
