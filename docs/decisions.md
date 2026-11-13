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

## Phase 2 — malicious test server

- **`servers/evil` is built on the low-level `Server`, not `MCPServer`.** The rug pull needs the
  tool list to change between `tools/list` calls, and the poisoned descriptions must reach the
  wire byte for byte, invisible characters included — neither survives schema generation from a
  decorated Python function.
- **Every hostile string lives in one module, `servers/evil/payloads.py`.** The scanner tests, the
  red-team cases and the threat model all cite the same constants, and a reviewer can see the
  whole hostile surface of this repo in one file.
- **An AST scan, not a grep, proves the server is inert.** `tests/unit/test_evil_server_is_inert.py`
  walks the package's syntax tree for forbidden imports, dotted calls (`os.remove`, `os.system`)
  and builtins (`open`, `eval`), and fails if the package gains a module that the scan does not
  cover. A grep is defeated by an alias; this is what makes the red-team suite safe to trust.
- **Behaviour is fixed by environment variables, never randomness.** `EVIL_RUGPULL_AFTER` and
  `EVIL_INJECTION_VARIANT` make each attack reproducible, which is what lets the red-team report
  be compared against a baseline.
- **`huge_output` and `slow_tool` are capped.** A test asking for a gigabyte must not take the
  machine down with it; the cap is 4 MB and 30 seconds.

## Phase 3 — proxy core

- **The upstream liveness probe is `tools/list`, not `ping`.** `ping` was removed from the
  protocol in 2026-07-28, so pinging a modern upstream answers "method not found" — the first
  version of the health loop marked every healthy server down every five seconds. Re-listing is
  the probe *and* the refresh, and a changed listing fires a callback, which is how a rug pull
  gets noticed between calls rather than only on restart.
- **`cache_mode="bypass"`, not `"skip"`.** The SDK's values are `use`, `refresh` and `bypass`;
  `"skip"` type-checked as a string and silently did something undefined. The gateway's upstream
  clients are also built with `cache=None`, because a cached tool listing would hide a rug pull.
- **One owner task per upstream.** The SDK client is an anyio context manager, so it must be
  entered and exited in the same task. The owner task enters it, publishes the session, holds and
  probes it, then exits it; request handlers only use the published session, which is safe across
  tasks. Each connection also has its own backoff and its own concurrency semaphore, so a slow
  upstream cannot stall another.
- **A stage that raises is a denial, not a 500.** `Pipeline.run` catches per stage and sets
  `WARDEN_DENIED:internal`. A bug in a security stage must not become an allowed call.
- **Finish hooks run in a `finally`, and a failing hook does not stop the others.** The audit
  writer is a finish hook; "every request leaves a record" depends on this.
- **Denials are `CallToolResult(isError=True)` with structured content**, not JSON-RPC errors.
  The caller is usually a model, which needs a reason code it can act on. Only protocol-level
  problems (bad credential, malformed request) use HTTP or JSON-RPC errors.
- **An upstream's own exception text is logged, never returned.** It can carry a path, a query or
  a connection string; the client gets `WARDEN_UPSTREAM_ERROR` and a request id.
- **`warden tools` renders descriptions with invisible characters escaped as `<U+200B>`.**
  Printing an untrusted description raw lets a poisoned tool hide text from the operator reading
  the tool list, which is the attack itself.
- **The app publishes its event loop on `app.state.loop`.** Upstream connections are owned by
  tasks in that loop; anything outside it (a test, operational tooling) must schedule work with
  `run_coroutine_threadsafe` instead of awaiting them directly.

## Phase 4 — authentication

- **A credential's *shape* picks the verifier; it never decides trust.** `wdn_` goes to the API
  key store, three dot-separated segments to the token verifier, anything else is refused
  without a database lookup. This keeps a JWT from being pointlessly hashed and looked up, and
  keeps an unknown format from reaching either backend.
- **The `alg` header is checked before any key material is loaded.** PyJWT is also given exactly
  one algorithm, so even if the pre-check were removed it would not consult the token's own
  claim. That one rule kills `alg=none`, HS256-with-the-published-public-key and
  RS256 substitution together.
- **The HS256 confusion test builds the token by hand.** PyJWT refuses to *encode* HS256 with a
  PEM key, but an attacker has no such guardrail, so the test HMACs the signing input with the
  public key bytes directly. Testing it through PyJWT's encoder would have tested PyJWT's
  guardrail, not ours.
- **An API key's prefix only narrows the lookup.** Two keys that share a prefix are both
  fetched and separated by a full `hmac.compare_digest` on the hash. A test constructs a real
  collision rather than faking one — the first version of that test was a no-op stub that passed
  for the wrong reason.
- **Two active signing keys, retired keys rejected rather than merely unverifiable.** A rotation
  must not invalidate tokens already in flight, but a retired key must not be a lingering
  signer; `jwks()` publishes only active keys and `verify` refuses any other `kid`.
- **If we cannot tell whether a token was revoked, we refuse it.** A Redis failure propagates out
  of `verify`, the middleware turns it into a 401, and the reason given to the caller is
  "authentication is unavailable" (hard rule 1).
- **401s never echo the credential**, and the reason is coarse ("unknown API key", not which
  part was wrong). A test asserts the presented secret appears in neither body nor headers.
- **Credentials are never forwarded upstream, structurally rather than by filtering.** The
  gateway builds upstream connections from `servers.yaml` alone, so there is no code path that
  could pass a client header through. A header-recording MCP server behind the gateway proves it.
- **Alembic for deployment, `metadata.create_all` for tests, plus a drift test.** Running
  migrations per test is slow; letting the two diverge is worse. The drift test reflects an
  Alembic-migrated SQLite database and compares tables and columns against the models.
- **The migration template imports `warden.db.base` and `Text` unconditionally.** Alembic's
  autogenerate emits `warden.db.base.UtcDateTime(...)` and `JSONB(astext_type=Text())` without
  adding the imports, so a freshly generated migration does not run.
- **Test setup runs on its own loop in a worker thread.** A SQLAlchemy async engine binds its
  connections to the loop that creates them, and the gateway under test runs in a uvicorn
  thread; sharing one engine across both loops fails at the first query.
