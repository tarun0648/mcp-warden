# Architecture

## What this is

mcp-warden is a reverse proxy for the Model Context Protocol. One endpoint, `/mcp`, speaks
Streamable HTTP to clients. Behind it, the gateway is itself an MCP *client* of several upstream
MCP servers, reached over stdio (a child process) or Streamable HTTP.

To a client the gateway looks like a single MCP server whose tools are named
`<server>__<tool>`. The client never learns which upstream served a call, never receives an
upstream's own error text verbatim, and never has its credential forwarded anywhere.

## Protocol versions

- SDK: the official Python SDK, pinned at `mcp==2.3.0`.
- Modern protocol version served and spoken: **2026-07-28**.
- Handshake-era versions the SDK still negotiates with older peers: 2024-11-05, 2025-03-26,
  2025-06-18, 2025-11-25.

The SDK's `mode="auto"` probes `server/discover` and falls back to the `initialize` handshake,
so both eras work. One consequence shaped the code: `ping` was **removed** in 2026-07-28, so the
gateway's upstream liveness probe is `tools/list`, not `ping`. Pinging a modern upstream answers
"method not found", which would mark every healthy server down.

## Components

| Component | File | Job |
| --- | --- | --- |
| App factory | `src/warden/main.py` | Builds the Starlette app: `/mcp`, `/healthz`, `/readyz`, and later the JWKS document, admin API and approval UI |
| MCP server | `src/warden/proxy/server.py` | The low-level `Server` with `on_list_tools` / `on_call_tool`; turns MCP requests into pipeline runs |
| Pipeline | `src/warden/pipeline.py` | `RequestContext`, the `Stage` protocol, and the runner that orders stages, times them and always runs the finish hooks |
| Registry | `src/warden/proxy/registry.py` | The namespaced tool map, rebuilt whenever an upstream's listing changes |
| Upstream manager | `src/warden/upstream/manager.py` | One owner task per upstream: connect, hold, probe, reconnect with backoff, report health |
| Config | `src/warden/config.py` | Strict, frozen Pydantic models for `gateway.yaml`, `servers.yaml` and `policies.yaml` |

## Request flow: `tools/call`

```
client --POST /mcp--> Streamable HTTP session manager --> on_call_tool
                                                             |
                                                      RequestContext
                                                             |
   authenticate -> resolve -> definition integrity -> policy -> rate limit + budget
      -> argument DLP -> approval -> FORWARD (timeout) -> output scan
                                                             |
                                            finish hooks (audit log, metrics, traces)
                                                             |
client <-- CallToolResult, or isError with a WARDEN_* reason code
```

Stages added per phase: `resolve` and `forward` in Phase 3; `authenticate` in 4; `policy` in 5;
`ratelimit` in 6; the audit finish hook and write-ahead in 7; `definitions`, `dlp` and
`output_scan` in 8; `approval` in 9.

Two properties hold at every phase:

1. **The pipeline stops at the first stage that refuses.** Nothing after it runs, so a denied
   call is never forwarded.
2. **The finish hooks always run** — after a denial, after a success, and after a stage raises.
   The audit writer is a finish hook, which is what makes "every request leaves a record" true.

A stage that raises becomes `WARDEN_DENIED:internal`, never an allow. A broken security check
must fail closed (hard rule 1).

## Request flow: `tools/list`

```
client --> on_list_tools --> principal resolver --> registry.definitions()
                                                 --> policy filter (Phase 5)
                                                 --> pin/quarantine filter (Phase 8)
```

Tools of an upstream that is currently down are simply absent: the registry is rebuilt from the
upstreams that are up, so the gateway never advertises a name that cannot work.

## Why one owner task per upstream

The SDK's client is an anyio context manager. Entering it in one task and leaving it in another
raises "attempted to exit cancel scope in a different task", so each upstream gets a dedicated
task that enters the client, publishes the session, holds it, and exits it — all in one task.
Request handlers only ever *use* the published session, which is safe across tasks.

The same constraint shapes the tests: they enter MCP clients inside the test body rather than in
an async fixture, and a test that needs to touch an upstream connection schedules the work on
the server's own loop with `run_coroutine_threadsafe`.

Each connection has its own backoff, its own health state and its own concurrency semaphore, so
one slow or dead upstream cannot stall another.

## Failure mapping

| Situation | What the client gets |
| --- | --- |
| Unknown or unregistered tool | `WARDEN_UNKNOWN_TOOL` |
| Upstream down or disconnected | `WARDEN_UPSTREAM_UNAVAILABLE` |
| Upstream exceeded its timeout | `WARDEN_UPSTREAM_TIMEOUT` |
| Upstream raised | `WARDEN_UPSTREAM_ERROR` (its own message is logged, not returned) |
| A pipeline stage raised | `WARDEN_DENIED:internal` |
| Bad or missing credential | HTTP 401 with `WWW-Authenticate` (a protocol problem, not a tool result) |

Every one of these is a `CallToolResult` with `isError=true` and a `structured_content` body
carrying `error`, `reason` and `request_id`, because the caller is usually a model that has to
understand what happened.
