# Decisions

One line per decision, with the reason. Newest last.

## Phase 0 — scaffold

- **MCP SDK pinned at `mcp==2.3.0`.** This is the v2 SDK: `FastMCP` was renamed to `MCPServer`,
  the low-level `Server` takes `on_list_tools` / `on_call_tool` constructor callbacks instead of
  decorators, and the types moved to a separate `mcp_types` package with snake_case fields and
  camelCase aliases. Pinning exactly means an SDK release cannot silently change the gateway's
  wire behaviour.
- **Python 3.12, not 3.13+.** `uv` manages the interpreter so the version is reproducible; 3.12 is
  what the ML extra (torch) supports best on Apple Silicon.
- **Config is strict (`extra="forbid"`) and frozen.** A typo in a security file must fail at load
  time rather than silently fall back to a default that widens access.
- **Config models are also frozen (immutable).** A live policy object cannot be mutated by a
  request handler, so hot reload is the only way the policy changes.
- **`redact()` matches key *segments*, not substrings.** Substring matching treated `secretary`
  and `tokenizer` as credentials; segment matching keeps `auth_token` secret while leaving
  `note_id` alone. Plural forms (`tokens`, `secrets`) are still redacted on purpose — losing one
  debugging field costs less than leaking one credential.
- **Client-supplied `x-request-id` is sanitised before use.** It lands in every JSON log line, so
  an unchecked value is a log-injection vector; anything outside `[A-Za-z0-9_-]{1,64}` is replaced
  with a fresh id.
- **SQLite (aiosqlite) is a first-class target alongside Postgres.** The same SQLAlchemy models run
  on both, so unit tests cover the audit log, pins and approvals without Docker; Postgres-only
  features (advisory locks, role grants) are behind a dialect check.
- **Integration tests skip, rather than fail, when Postgres or Redis is not listening.** A missing
  Docker daemon is an environment problem, not a regression; CI provides the services so the same
  tests run for real there.
- **Readiness checks run concurrently with a per-check timeout.** A hanging dependency must not
  make `/readyz` itself hang, or the gateway looks alive to a load balancer while it is not.
