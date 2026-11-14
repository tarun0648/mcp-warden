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
| App factory | `src/warden/main.py` | Builds the Starlette app: `/mcp`, `/healthz`, `/readyz`, the JWKS and RFC 9728 metadata documents, `/metrics`, the admin API and the approval UI |
| HTTP edge | `src/warden/http_limits.py` | Request body limit (413) and JSON-RPC batch refusal, before anything parses the body |
| MCP server | `src/warden/proxy/server.py` | The low-level `Server` with `on_list_tools` / `on_call_tool`; turns MCP requests into pipeline runs |
| Pipeline | `src/warden/pipeline.py` | `RequestContext`, the `Stage` protocol, and the runner that orders stages, times them and always runs the finish hooks |
| Registry | `src/warden/proxy/registry.py` | The namespaced tool map, rebuilt whenever an upstream's listing changes |
| Upstream manager | `src/warden/upstream/manager.py` | One owner task per upstream: connect, hold, probe, reconnect with backoff, report health |
| Config | `src/warden/config.py` | Strict, frozen Pydantic models for `gateway.yaml`, `servers.yaml` and `policies.yaml` |

## Request flow: `tools/call`

```
client --POST /mcp--> request id -> body/batch limits -> auth middleware
                  --> Streamable HTTP session manager (Host/Origin checks) --> on_call_tool
                                                             |
                                                      RequestContext
                                                             |
   authenticate -> resolve -> definition integrity -> schema defaults -> policy -> rate limit + budget
      -> argument DLP -> approval -> FORWARD (timeout) -> output scan
                                                             |
                                            finish hooks (audit log, metrics, traces)
                                                             |
client <-- CallToolResult, or isError with a WARDEN_* reason code
```

Stages added per phase: `resolve` and `forward` in Phase 3; `authenticate` in 4; `policy` in 5;
`ratelimit` in 6; the audit finish hook and write-ahead in 7; `definitions`, `dlp` and
`output_scan` in 8; `approval` in 9. Phase 13 added the HTTP-edge limits in front of the
transport; they are middleware rather than stages because they must run before the body is
parsed, and a stage only ever sees a parsed request. After v0.1.0, `defaults` joined between `definitions` and
`policy`: it fills omitted arguments from the pinned schema so the constraints check what will
be forwarded (`src/warden/policy/defaults.py`).

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

## Observability

### Tracing

The SDK does two parts of this already, so the gateway builds on them rather than duplicating
them:

- **The root span.** `mcp.server._otel.OpenTelemetryMiddleware` is installed by default on the
  low-level `Server`, so every inbound request gets a SERVER span with the current semantic
  conventions: `mcp.method.name`, `mcp.protocol.version`, `jsonrpc.request.id`, and for a tool
  call `gen_ai.operation.name = "execute_tool"` plus `gen_ai.tool.name`.
- **Context propagation.** The SDK's JSON-RPC dispatcher injects W3C `traceparent` into
  outbound `_meta`, so an upstream running the SDK joins the same trace. There is an
  integration test for it rather than an assumption.

The gateway adds one `warden tools/call` span per request and one `stage <name>` span per
pipeline stage. Attributes used, beyond the SDK's:

| Attribute | Meaning |
| --- | --- |
| `warden.request.id` | The id echoed in `x-request-id` and in every audit row |
| `warden.principal.id`, `warden.auth.method` | Who called, and with which credential type |
| `warden.stage` | Which pipeline stage this span is |
| `warden.decision`, `warden.reason_code` | `allow` / `deny` / `pending`, and the `WARDEN_*` code |
| `warden.matched_rule` | The policy rule that decided |
| `warden.risk` | `read` / `write` / `destructive` |
| `warden.upstream`, `warden.forwarded` | Which server, and whether it was actually reached |
| `warden.result.bytes` | Size only, never content |
| `warden.scan.verdict`, `warden.scan.rules` | What the scanners found |
| `warden.classifier.score` | The local classifier's probability, when it ran |
| `warden.approval.id`, `warden.quarantine.reason` | Why a call waited or was refused |
| `error.type` | Set to the reason code on a denial, which also sets span status ERROR |

**No argument, result or credential is ever a span attribute.** Spans go to a collector that is
normally outside the trust boundary the audit log sits inside, and nothing downstream redacts
them. `set_attributes` enforces an allowlist and logs an error if code tries to set anything
else, so one hurried `span.set_attribute("args", ...)` cannot leak call arguments. Two tests
cover it: a canary check over every span and event, and a direct attempt to set a
non-allowlisted attribute.

Every log line emitted while handling a request carries `trace_id` and `span_id`, so a log
line can be followed into its trace.

### Metrics

`/metrics` in Prometheus text format. Served to loopback without a credential — that is how a
sidecar Prometheus scrapes it — and to the `admin` role otherwise; `METRICS_ALLOW_LOCALHOST=false`
requires the credential from everywhere. `METRICS_ALLOW_NETWORKS` adds named CIDRs - compose
sets its own bridge subnet, because a Prometheus *container* does not scrape from loopback.
The endpoint is on the auth middleware's *optional*
list: a credential is verified if present and not required, so the endpoint itself can make
that choice.

| Metric | Type | Labels |
| --- | --- | --- |
| `warden_requests_total` | counter | `decision`, `reason`, `tool` |
| `warden_denials_total` | counter | `reason` |
| `warden_stage_duration_seconds` | histogram | `stage` |
| `warden_upstream_duration_seconds` | histogram | `upstream` |
| `warden_upstream_up`, `warden_upstream_tools` | gauge | `upstream` |
| `warden_quarantined_tools`, `warden_pending_approvals` | gauge | — |
| `warden_classifier_seconds` | histogram | — |

Label cardinality is the design constraint. `tool` is bounded by the registry and anything not
in it is recorded as the literal `unknown`, so a caller inventing names cannot create a time
series per name. `principal` is not a label at all: it is unbounded by definition, and
per-caller usage already lives in the audit log and `/admin/usage`.

`make up-observability` starts Prometheus (`:9090`) and Grafana (`:3000`) with the datasource
and the `mcp-warden` dashboard provisioned from `deploy/grafana/`.

## Deployment

`make up-all` runs the whole stack in containers: the gateway (its stdio upstreams are child
processes inside the same container, launched by the same `servers.yaml` as on a laptop),
Postgres, Redis, Jaeger, Prometheus and Grafana.

| Concern | How |
| --- | --- |
| Image | two stages; base images pinned by tag and digest; `uv sync --frozen`; `WITH_ML` build arg |
| Privileges | uid 10001, no login shell, `cap_drop: [ALL]`, `no-new-privileges` |
| Filesystem | `read_only: true`; `/tmp` is a tmpfs; keys, notes database, sandbox and model cache are named volumes under `/var/lib/warden` |
| Startup | the entrypoint runs `warden db upgrade` and `warden keys init-jwt` (both idempotent), then `serve` |
| Network | every port published on 127.0.0.1 only; a fixed bridge subnet so `/metrics` can name its scraper |
| Health | the image's healthcheck is `/healthz` (liveness); `/readyz` checks Postgres and Redis |

Liveness says nothing about upstreams. The first containerised run was healthy with both
upstreams down (see the Phase 13 entry in `docs/decisions.md`); `warden tools list` or an
actual MCP session is the check that the gateway can do its job.

