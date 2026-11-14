# Where the build stands

All fourteen phases (0-13) are complete, one commit per phase, and `v0.1.0` is tagged. Nothing is
half-finished.

## Verified state at v0.1.0

- `make lint` clean: ruff check, ruff format --check, mypy --strict on `src/warden` and `servers`.
- `make test`: 1323 passed, unit + integration, against real Postgres and Redis.
- `make test-all`: every layer; the five `e2e` tests skip because Ollama is not installed here.
- `make cov`: 94.27% on `src/warden` against an 85% gate.
- `make security`: bandit clean (two justified `nosec`), pip-audit clean.
- `make redteam`, `make bench`, `make soak`, `make demo`: results in `results/`, summarised in the
  README by `make readme-results`.
- `make up-all`: verified end to end - a real MCP session through the containerised gateway,
  writes landing on the volumes, a policy denial, `warden audit verify` OK, Prometheus scraping
  the container, Jaeger receiving its traces.

## Outstanding, and why

| Item | State |
| --- | --- |
| 2-minute demo video | Not recorded: it needs a person and a screen recorder. The README says so instead of linking to nothing. |
| Real-model demo runs | Ollama is not installed on this machine. `brew install ollama && ollama pull qwen2.5:7b`, then `make demo-real`. The `e2e` tests are written and skip cleanly until then. |
| Repository public, resume and site links | The maintainer's call. |
| Cursor and Claude Desktop | Not driven here; `docs/clients.md` labels exactly which steps were run and which come from vendor documentation. |

## Known gaps worth fixing next

Full list in `docs/threat-model.md#known-gaps`. The two most actionable:

1. **A constraint on an absent optional argument denies** (`files__list_files {}`). Fill the
   default from the pinned schema, check it, forward exactly what was checked.
2. **The gateway advertises itself as an OAuth authorization server it is not.** Either delegate
   to a real one or stop naming it in the RFC 9728 metadata.

## Backing services on this machine

Homebrew Postgres 17 (on 5432) and Redis (on 6379) serve the test suite. Compose's own Postgres
and Redis publish on the same ports by default, so `make up-all` was run here with
`POSTGRES_HOST_PORT=55432 REDIS_HOST_PORT=56379`. On a machine without a local Postgres or Redis
the defaults work as they are.

## Things that are easy to re-break

Full reasoning for each is in `docs/decisions.md`:

1. `ping` was removed in protocol 2026-07-28; the upstream liveness probe is `tools/list`.
2. The SDK's cache modes are `use` / `refresh` / `bypass`; `"skip"` type-checks and does nothing.
3. Alembic's `fileConfig` needs `disable_existing_loggers=False`.
4. A policy glob must never cross `__`, and a deny rule may not carry constraints.
5. `redact()` matches key *segments*, not substrings.
6. The SDK spawns stdio upstreams with an almost empty environment. Anything an upstream needs
   goes in its `env:` in `servers.yaml`; only the six named `uv` launcher settings are forwarded.
7. A container's `/healthz` says nothing about upstreams. Check with a real session.
8. Enter MCP clients inside the test body, never in an async fixture (anyio task affinity).
9. Every number in the README comes from `results/` via `make readme-results`, and a test fails
   if the block is stale.
