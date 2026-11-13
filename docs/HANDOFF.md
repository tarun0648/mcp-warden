# Where the build stands

Phases 0–6 are complete, tested and committed, one commit per phase. Phases 7–13 are not
started. Nothing is half-finished: every committed phase passes `make lint` and `make test`.

## Verified state at the last commit

- `make lint` clean: ruff check, ruff format --check, mypy --strict on `src/warden` and `servers`.
- `make test` green: **601 passed, 0 skipped** (unit + integration), with real Postgres and Redis.
- `warden check-config`, `warden tools`, `warden keys`, `warden token`, `warden db upgrade` all
  exercised by hand against the real upstream servers.

## Backing services on this machine

Docker Desktop was not running, so the Homebrew Postgres 17 and Redis already installed on the
Mac were used instead of `make up`:

```bash
redis-server --port 6379 --daemonize yes --save '' --appendonly no
pg_ctl -D ~/.local/share/warden-pgdata -l ~/.local/share/warden-pgdata/server.log -o "-p 5432 -k /tmp" start
```

The `warden` role and `warden` database were created with the password from `.env.example`.
`docker compose up -d --wait` is still the documented path and should work unchanged once
Docker is running; the integration tests skip cleanly when neither is listening.

Ollama is **not** installed, so Phase 12's real-Ollama runs cannot be exercised on this machine
yet (`brew install ollama && ollama pull qwen2.5:7b`). The Phase 12 plan already calls for a
fake scripted LLM so the scenario assertions run in CI without it.

## Resume instructions

Start a fresh session per phase, as `CLAUDE.md` says, and paste the next phase prompt from
`MCP Gateway — Step-by-Step Build Prompts.md`. Begin with **Phase 7 — tamper-evident audit log**.

Phase 7 can build on what already exists:

- `src/warden/db/` has the engine, the declarative base, `UtcDateTime`, `JsonColumn`, and
  `Database.transaction_with_lock()` — already written for the audit chain, taking
  `pg_advisory_xact_lock` on Postgres and relying on SQLite's file lock otherwise
  (`AUDIT_CHAIN_LOCK_KEY` is reserved for it).
- `warden.pipeline.Pipeline` already runs **finish hooks in a `finally`**, after a denial, a
  success *and* a stage exception. The audit writer is meant to be one of those hooks; that is
  what makes "every request leaves a record" true.
- `RequestContext` already carries everything a row needs: `request_id`, `principal`,
  `tool_name`, `upstream`, `risk`, `arguments`, `stage_timings_ms`, `decision`, `reason_code`,
  `matched_rule`, `scan_flags`, `result_bytes` and `forwarded` (which distinguishes "denied
  before forwarding" from "forwarded and then refused").
- `warden.logging.redact()` is the single redaction point for `args_redacted`.
- Migrations: `uv run alembic revision --autogenerate -m "audit events"`. The template already
  imports `warden.db.base` and `Text`, which autogenerate needs but does not add.
- `tests/integration/test_schema_and_revocation.py` has the Alembic-vs-metadata drift test; a
  new table is covered by it automatically.
- Turn on the coverage gate in CI at the end of Phase 7 (`make cov`, `--cov-fail-under=85`).

## Test harness worth knowing about

`tests/helpers.py` is the whole integration story:

- `running_gateway(tmp_path, ...)` serves the real app under uvicorn on a free port, in front of
  real upstream subprocesses, and mints one API key per test role (`gateway.auth("reader")`).
- `gateway_client(handle, headers)` is an MCP client over real Streamable HTTP.
- Enter MCP clients **inside the test body**, never in an async fixture: the SDK client is an
  anyio context manager and crossing tasks raises "cancel scope in a different task".
- `handle.on_server_loop(coro)` schedules work on the gateway's own event loop; awaiting an
  upstream connection directly fails with "attached to a different loop".
- `run_async(factory)` runs setup on a fresh loop in a worker thread, because a SQLAlchemy async
  engine binds its connections to the loop that created them.
- `policies_allowing(role, rule_id, tools)` extends the shipped policy for upstreams that only
  exist in a test.

## Things found while building that are easy to re-break

Full reasoning for each is in `docs/decisions.md`:

1. `ping` was removed in protocol 2026-07-28 — the upstream liveness probe must be `tools/list`.
2. The SDK's cache modes are `use` / `refresh` / `bypass`; `"skip"` type-checks and does nothing.
3. Alembic's `fileConfig` needs `disable_existing_loggers=False` or it silences warden's logging.
4. A glob in a policy must never cross `__`, and a pattern naming no server is a load-time error.
5. A deny rule may not carry argument constraints — the condition would become the bypass.
6. `redact()` matches key *segments*, not substrings.
