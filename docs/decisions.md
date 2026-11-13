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

## Phase 1 — benign upstream servers

- **`run_sql` is guarded four ways, not one.** A parser-level check (single statement, starts with
  SELECT, no forbidden keyword), a read-only connection URI, a deny-by-default SQLite authorizer,
  and Python's own `execute()` refusal of multi-statement SQL. Any one of them can be wrong.
- **Forbidden SQL keywords are matched on word boundaries.** Matching `" delete "` with spaces let
  `WITH x AS (DELETE ...)` and `load_extension(` through, because the keyword was followed by a
  paren. Boundary matching also keeps the column name `created` from looking like `CREATE`.
- **String literals and comments are blanked, not removed, before the keyword check.** Blanking
  keeps offsets stable, so `WHERE body LIKE '%drop table%'` is allowed while a real `DROP` is not.
- **A `WITH` statement must contain a SELECT outside its CTE bodies.** Looking for `select`
  anywhere accepted the incomplete `WITH t AS (SELECT 1)`.
- **Percent-encoded paths are refused, never decoded.** Decoding is what turns `%2e%2e/x` into
  traversal; a literal `%` in a sandbox filename is a cost worth paying.
- **Path safety resolves the deepest existing ancestor and re-appends the rest.** Resolving only
  the leaf misses a symlinked directory in the middle of the path, and resolving a non-existent
  leaf would break `write_file`.
- **Tools raise the SDK's `ToolError`, not `ValueError`.** `ToolError` returns the message to the
  caller as an `is_error` result and logs at INFO; any other exception becomes
  `UnexpectedToolError`, whose message is only "Error executing tool X" with a traceback in the
  server log. Anticipated failures deserve a readable reason.
- **Tests enter the MCP client inside the test body, not in an async fixture.** The SDK's client is
  an anyio context manager; entering it in a pytest async fixture and exiting it in the finaliser
  crosses tasks, which anyio rejects with "cancel scope in a different task".
