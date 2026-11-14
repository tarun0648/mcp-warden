"""The request-limits middleware, driven as raw ASGI. No server, no network.

The downstream app here is a recorder, not a mock of the thing under test: the middleware is
the component under test and runs for real; the recorder only reports what reached it.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from warden.http_limits import INVALID_REQUEST, RequestLimitsMiddleware

pytestmark = [pytest.mark.unit, pytest.mark.anyio]

LIMIT = 1024


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Recorder:
    """A downstream ASGI app that reads the whole body and answers 200 with its length."""

    def __init__(self) -> None:
        self.calls = 0
        self.bodies: list[bytes] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.calls += 1
        chunks = []
        while True:
            message = await receive()
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        self.bodies.append(body)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": str(len(body)).encode()})


def scope(path: str = "/mcp", method: str = "POST", length: int | None = None) -> dict[str, Any]:
    headers = [(b"content-type", b"application/json")]
    if length is not None:
        headers.append((b"content-length", str(length).encode()))
    return {"type": "http", "method": method, "path": path, "headers": headers}


def receiver(*chunks: bytes) -> Any:
    queue = list(chunks)

    async def receive() -> dict[str, Any]:
        if not queue:
            return {"type": "http.disconnect"}
        chunk = queue.pop(0)
        return {"type": "http.request", "body": chunk, "more_body": bool(queue)}

    return receive


async def run(
    middleware: RequestLimitsMiddleware, request_scope: dict[str, Any], *chunks: bytes
) -> tuple[int, bytes]:
    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await middleware(request_scope, receiver(*chunks), send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


def make(app: Recorder) -> RequestLimitsMiddleware:
    return RequestLimitsMiddleware(app, max_body_bytes=LIMIT, mcp_path="/mcp")


# -- size --------------------------------------------------------------------------------------


async def test_a_body_under_the_limit_reaches_the_app_unchanged() -> None:
    app = Recorder()
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    status, _ = await run(make(app), scope(length=len(body)), body)
    assert status == 200
    assert app.bodies == [body]


async def test_a_body_exactly_at_the_limit_is_accepted() -> None:
    app = Recorder()
    body = b"{" + b" " * (LIMIT - 2) + b"}"
    status, _ = await run(make(app), scope(length=LIMIT), body)
    assert status == 200


async def test_a_declared_oversize_body_is_refused_before_it_is_read() -> None:
    app = Recorder()
    status, body = await run(make(app), scope(length=LIMIT + 1), b"x" * (LIMIT + 1))
    assert status == 413
    assert app.calls == 0, "the app must never see an oversized request"
    assert json.loads(body)["error"] == "payload_too_large"


async def test_an_undeclared_oversize_body_is_refused_while_streaming() -> None:
    """Chunked encoding has no Content-Length to check; the bytes are counted instead."""
    app = Recorder()
    chunks = [b"x" * 400] * 4  # 1600 bytes, never declared
    status, _ = await run(make(app), scope(length=None), *chunks)
    assert status == 413
    assert app.calls == 0


async def test_a_lying_content_length_does_not_get_a_larger_body_through() -> None:
    """A small declared length followed by a large body is still counted."""
    app = Recorder()
    status, _ = await run(make(app), scope(length=10), b"x" * 600, b"x" * 600)
    assert status == 413
    assert app.calls == 0


async def test_non_mcp_paths_are_limited_too() -> None:
    """The approval form and the admin API are held to the same limit."""
    app = Recorder()
    status, _ = await run(
        make(app), scope(path="/approvals/decide", length=None), b"x" * 600, b"x" * 600
    )
    assert status == 413


async def test_non_mcp_paths_under_the_limit_stream_through() -> None:
    app = Recorder()
    status, _ = await run(make(app), scope(path="/admin/policies"), b"a=1", b"&b=2")
    assert status == 200
    assert app.bodies == [b"a=1&b=2"]


async def test_a_get_is_never_inspected() -> None:
    app = Recorder()
    status, _ = await run(make(app), scope(method="GET", length=LIMIT * 10), b"")
    assert status == 200


async def test_a_garbage_content_length_falls_back_to_counting() -> None:
    app = Recorder()
    request = scope()
    request["headers"].append((b"content-length", b"not-a-number"))
    status, _ = await run(make(app), request, b"x" * (LIMIT + 5))
    assert status == 413


def test_a_zero_limit_is_a_configuration_error() -> None:
    with pytest.raises(ValueError):
        RequestLimitsMiddleware(Recorder(), max_body_bytes=0)


# -- batches -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]',
        b'  \n[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]',
        b"\xef\xbb\xbf[]",
        b"[]",
    ],
)
async def test_a_batch_is_refused_with_a_json_rpc_error(body: bytes) -> None:
    app = Recorder()
    status, payload = await run(make(app), scope(length=len(body)), body)
    assert status == 400
    assert app.calls == 0, "a batch must not reach the transport"
    error = json.loads(payload)
    assert error["jsonrpc"] == "2.0"
    assert error["error"]["code"] == INVALID_REQUEST
    assert "batch" in error["error"]["message"].lower()


async def test_a_single_request_is_not_mistaken_for_a_batch() -> None:
    app = Recorder()
    body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":[1,2]}}'
    status, _ = await run(make(app), scope(length=len(body)), body)
    assert status == 200


async def test_an_array_body_elsewhere_is_not_treated_as_a_batch() -> None:
    """The batch rule is about JSON-RPC, so it applies to the MCP endpoint only."""
    app = Recorder()
    status, _ = await run(make(app), scope(path="/admin/keys", length=2), b"[]")
    assert status == 200


async def test_malformed_json_is_left_to_the_transport() -> None:
    """The transport answers that with a proper parse error; duplicating it here would drift."""
    app = Recorder()
    status, _ = await run(make(app), scope(length=5), b"{oops")
    assert status == 200
    assert app.bodies == [b"{oops"]


async def test_a_trailing_slash_on_the_mcp_path_is_still_the_mcp_path() -> None:
    app = Recorder()
    status, _ = await run(make(app), scope(path="/mcp/", length=2), b"[]")
    assert status == 400
