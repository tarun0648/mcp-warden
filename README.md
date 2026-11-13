# mcp-warden

**A security gateway for the Model Context Protocol.** It sits between MCP clients (Claude
Desktop, Cursor, the MCP Inspector, a local agent) and the MCP servers they use. To the client it
looks like one MCP server; to the servers it looks like one MCP client. Every `tools/list` and
`tools/call` crosses a pipeline that authenticates the caller, checks a deny-by-default policy
including per-argument constraints, enforces rate limits and daily budgets, scans arguments for
secrets and tool definitions and results for prompt injection, asks a human to approve destructive
calls, and records the whole thing in a hash-chained, insert-only audit log. It fails closed: if
the policy store, the limiter, the audit log or a scanner is unavailable, the call is denied.

## Status

| Phase | What it adds | State |
| --- | --- | --- |
| 0 | Scaffold, strict config, redaction, health checks, CI | done |
| 1 | `notes_db` and `files` upstream MCP servers | done |
| 2 | `evil` malicious server for the red-team suite | done |
| 3 | Transparent MCP proxy and pipeline skeleton | done |
| 4 | API-key and ES256 JWT auth, JWKS, no token passthrough | done |
| 5 | Deny-by-default policy engine with argument constraints | done |
| 6 | Atomic rate limits, daily budgets, output size caps | done |
| 7 | Insert-only hash-chained audit log | done |
| 8 | Definition pinning, rug-pull quarantine, DLP, injection scanning | done |
| 9 | Single-use human approvals with a web UI | done |
| 10 | OpenTelemetry traces, Prometheus metrics, Grafana | not started |
| 11 | Red-team suite and latency benchmark | not started |
| 12 | Local Ollama demo agent and attack scenarios | not started |
| 13 | Hardening, threat model, docs, v0.1.0 | not started |

## Setup on macOS

```bash
brew install uv docker docker-compose
cp .env.example .env          # then edit the password
make setup                    # creates the venv, installs deps and pre-commit hooks
make up                       # postgres, redis, jaeger
make test                     # unit + integration
```

Optional extras: `uv sync --extra ml` for the local prompt-injection classifier,
`brew install ollama && ollama pull qwen2.5:7b` for the demo agent. No paid LLM API is needed
anywhere; the gateway itself never calls an LLM.

## Make targets

Run `make help` for the full list. The ones you need most:

| Target | What it does |
| --- | --- |
| `make up` / `make down` | Start / stop Postgres, Redis and Jaeger |
| `make lint` | ruff check, ruff format --check, mypy --strict on `src/warden` |
| `make test` | Unit + integration tests |
| `make test-all` | Every layer, including e2e, ml, redteam and perf |
| `make run` | Run the gateway |
| `make inspector` | Point the MCP Inspector at the running gateway |
| `make redteam` / `make bench` | Write measured results into `results/` |

## Layout

```
src/warden/   gateway: config, auth, policy, ratelimit, audit, scan, approval, proxy, pipeline
servers/      upstream MCP servers we own (notes_db, files, and evil for tests only)
redteam/      attack and benign cases plus the runner
bench/        latency benchmark
config/       gateway.yaml, servers.yaml, policies.yaml
docs/         architecture.md, threat-model.md, decisions.md
results/      machine-written benchmark and red-team output
```

## License

MIT. See [LICENSE](LICENSE).
