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

## Phase 5 — policy engine

- **A glob never crosses the `__` separator**, enforced by matching the server part and the tool
  part separately. A pattern that names no server (`*`, `files`) is **rejected at config load**
  rather than silently matching nothing: a policy author writing `*` means "everything", and
  the safe answer is to tell them it is not allowed rather than to grant it or ignore it.
- **A server name may not contain `__`.** Otherwise `a__b` as a server name makes
  `split_namespaced` ambiguous and two different tools can resolve to one public name.
- **A deny rule may not carry argument constraints, and that is a load-time error.** If a deny
  could be conditional on an argument, the condition becomes the bypass: send the argument as
  the wrong type, the constraint stops matching, the deny stops applying, and an allow rule
  further down lets the call through.
- **A constraint can only narrow.** A missing argument, a wrongly typed one, or a numeric string
  where a number is expected all fail the constraint — so the allow rule does not apply. A
  numeric string is refused deliberately: the upstream would parse it, and we would not.
- **`regex` is a full match, never a search.** A search would let `../../etc/passwd` satisfy a
  pattern written for `[a-z]+\.md`.
- **`starts_with` compares normalised paths, segment by segment.** `notes/../secret` is checked
  as `secret`, and a prefix of `notes` does not match `notesecret`.
- **The shipped policy constrains file paths at the gateway, not only at the upstream.** Writing
  the test table turned up that `files__write_file` accepted `../a.md`: the regex allowed dots
  and slashes, so only the files server's sandbox stopped it. `starts_with: "."` normalises to
  the root, which means "a relative path that does not climb out", and now the call is refused
  before it is forwarded. Two independent layers, as the sandbox was always meant to be.
- **`tools/list` hides a tool whose only matching rule is a deny.** A reader should not learn
  that `files__delete_file` exists; argument constraints are ignored for listing, because a tool
  callable with *some* arguments is a tool you can see.
- **A rejected reload keeps the previous policy in force.** Falling back to an empty policy
  would deny everything (a self-inflicted outage) and falling back to a default would be worse.
  The rejection is logged at ERROR and the admin endpoint answers 409.
- **The policy stage reads the engine from the store on every request**, so a reload takes
  effect on the next call rather than the next restart.
- **Authentication is not authorisation.** `/admin` is behind the auth middleware *and* an
  explicit `admin` role check that answers 403 and logs the attempt.

## Phase 6 — rate limits, budgets, size limits

- **One Lua script decides every limit, all-or-nothing.** A limiter that reads, decides and
  writes as separate commands loses to concurrency: fifty simultaneous requests each read "10
  tokens left" and each allow themselves. The whole decision therefore runs inside a single
  `EVAL`. The script also refuses to charge anything unless *every* limit allows the call, which
  is stricter than checking each in turn and means a denied call never leaves a partial charge
  the caller cannot see. Tested with 50 concurrent calls against both fakeredis and a real
  Redis, asserting exactly the capacity passes.
- **`fakeredis[lua]`, not a Python reimplementation of the script.** Unit tests execute the
  same Lua the gateway ships. A second implementation next to the first would pass its own
  tests and prove nothing about production.
- **Bucket keys expire after a full refill plus a minute.** Once a bucket has refilled, its row
  is indistinguishable from a fresh one, so keeping it only costs memory.
- **Oversized *arguments* are refused locally, before Redis.** A giant payload should not cost a
  token or be shipped into a Lua script to be measured.
- **An oversized *result* is denied, never truncated.** A silently shortened tool result is a
  correctness bug in whatever reads it, and for a model it is worse than an error, because the
  model cannot tell that something is missing. `ctx.result` is cleared so no partial content can
  leak out of a later stage.
- **The limiter fails closed, and fail-open logs a warning every time the process starts.** The
  flag exists for local development; a gateway running without limits should be impossible to
  miss in the logs.
- **The clock is injected.** Refill-after-time and budget-reset-at-UTC-midnight are the two
  behaviours that would otherwise need `sleep` in a test.
- **Alembic's `fileConfig` is called with `disable_existing_loggers=False`.** The default (True)
  switches off every logger that already exists, including all of warden's. The test suite found
  it as an order-dependent failure, but it is a production bug too: a process that ran
  `warden db upgrade` and then served would lose its own logging.
- **Tests assert on log output with a handler attached to the specific logger, not `caplog`.**
  The gateway's `configure_logging` replaces the root handlers, so whether caplog's handler is
  still attached depends on test order.

## Phase 7 — tamper-evident audit log

- **The write-ahead row is the last stage before `forward`.** Everything that can refuse a call
  cheaply has already run, so the log is not filled with rows for calls that were never going to
  happen; and nothing that can reach an upstream runs before it.
- **`started` is written before the upstream is reached, and a failure to write it is a denial.**
  A gateway whose log is down must stop acting rather than keep acting unobserved. The closing
  row is best effort by contrast: by then the upstream has already run or been refused, so
  failing the request would change nothing and would hand the caller an error it cannot act on.
  A `started` row with no `finished` row is itself the evidence.
- **A call denied *after* forwarding is recorded as `finished`, not `denied`.** On a timeout the
  upstream may well have acted; a row saying "denied" would be a false statement about the world.
- **`row_hash` excludes `id`.** The database assigns it, so including it would make a row's hash
  depend on a sequence value that a restore or a burnt sequence number can change without anyone
  tampering. `prev_hash` is what orders the chain.
- **A test asserts that editing *any* hashed field changes the hash**, by mutating each field in
  turn. That is what stops a future field being added to the table but not to the hash.
- **Truncating the tail of the chain is not detectable from the chain alone**, and there is a
  test that says so. `warden audit verify` prints the head hash for exactly this reason; pinning
  it outside the gateway is the missing half, and it is listed as a known gap rather than
  implied to be solved.
- **Appends are serialised twice over**: an in-process `asyncio.Lock` and, on Postgres,
  `pg_advisory_xact_lock`. Two `AuditLog` instances standing in for two gateway processes have
  their own locks, so only the database-level one can keep them in step — tested with 50
  interleaved appends from two writers.
- **The migration never creates a role.** Creating one needs `CREATEROLE`, which a migration
  role usually does not have and should not need; `REVOKE ALL ... FROM PUBLIC` does run there,
  because leaving a PUBLIC grant undoes every other restriction. `warden db harden` does the
  privileged half, and `warden audit privileges <role>` reads back what Postgres actually
  permits. A test proves a non-owner member gets `permission denied` on UPDATE and DELETE.
- **`harden` validates its `--grant-to` argument before any side effect.** The first version
  quoted the identifier at the point of use, which meant a bad name left a half-applied state.
- **`Database.create_all()` imports the models itself.** A table only joins `Base.metadata` when
  its module has been imported, so a caller that had not happened to import `warden.db.models`
  got an empty metadata and a silent no-op — which is how a Postgres test ended up querying a
  table nothing had created.
- **Alembic's `Config` is constructed with an explicit `stdout`.** It binds `sys.stdout` as a
  *default argument*, so it captures whatever stdout existed at import time: the wrong stream
  after any redirect, and a closed one under a CLI test runner.
- **`warden token create` prints with `soft_wrap`.** rich otherwise breaks a long token across
  lines, and what the operator copies is then not a token.
- **The test harness loads the shipped `gateway.yaml`.** It previously used `GatewayConfig()`
  defaults, so integration tests were checking limits nobody deploys — which is how a
  "100 concurrent calls" test quietly became a "30 concurrent calls" test.
- **The CSV export leaves out the nested JSON columns.** Quoting rules for embedded JSON differ
  per spreadsheet; the JSON endpoint carries them faithfully instead.

## Phase 8 — content security

### The classifier is worth less than the rules, and the measurement says so

Measured on `tests/data` (46 attacks across 8 categories, 46 benign examples), with
`uv run pytest -m ml`:

| Configuration | Detection | False positives |
| --- | --- | --- |
| Rules only | 46/46 (100%) | 0/46 (0%) |
| Classifier only, at 0.999 | 32/46 (69.6%) | 2/46 (4.3%) |
| Rules + classifier | 46/46 (100%) | 2/46 (4.3%) |

On this set the classifier **adds no detection and costs two false positives**. It misses every
shadowing case, every exfiltration case and most tool-poisoning cases — because those attacks
are structural ("use this instead of `files__read_file`") rather than imperative, and a
prompt-injection classifier is trained on the imperative kind.

Three consequences, all of them in the code:

- **`classifier_threshold` defaults to 0.999, not 0.8.** At 0.8 the model flagged 17.4% of
  ordinary text; it scores *"Never store credentials in the repository; use the secret store."*
  at **1.0000** — identical to a real injection. A threshold sweep showed no value that
  separates the two classes on this set: 0.95 gives 78%/15%, 0.999 gives 70%/4%. 0.999 is the
  measured operating point, not a guess, and this is a change to a production default justified
  by data — the test's 85%/5% assertion was left where the plan put it.
- **A classifier hit can never decide on its own.** It is weighted `HIGH`, which reaches
  `suspicious` but not `malicious`, so a false positive costs a warning banner on a trusted
  server's output rather than a refused call. `test_a_classifier_hit_alone_can_never_block_or_quarantine`
  pins that.
- **The `ml` test reports the classifier-alone figure next to the combined one.** Reporting only
  the combined number would let the rules flatter the model, which is the sort of number hard
  rule 7 exists to prevent.

The honest caveat: the rules reach 100%/0% on a set **I wrote and then tuned two rules against**,
so that is not an independent benchmark. The classifier was never tuned against it, which is
part of why it looks worse. The red-team suite with a baseline comparison (Phase 11) is the
stronger measurement, and it reports both columns for the same reason.

### Everything else

- **Rules are specific, not keyword lists.** "ignore" alone is not a signal; "ignore all previous
  instructions" is. "password" alone is not a signal — a password-policy note is ordinary;
  "~/.ssh/id_rsa" is. Each rule has at least three positive and three negative examples, and the
  negatives are drawn from the notes and tool descriptions this project actually ships.
- **Two false positives found by writing the negatives first.** `credentials` as a bare word
  flagged the seeded note "Rotate credentials every 90 days", so the rule now requires a file
  context; `.env` flagged this repository's own `.env.example`, so that is excluded explicitly.
- **Text is NFKC-folded and invisible-stripped before matching**, so `i<ZWSP>gnore` and a
  fullwidth rendering are not bypasses, while the invisible characters are *also* reported as a
  finding in their own right.
- **Base64 is decoded one layer and re-scanned, never recursively.** Recursing on
  attacker-controlled data is how a scanner becomes the denial of service.
- **Each rule contributes at most once however many times it fires.** Forty zero-width
  characters are one unicode problem, not forty, or a single noisy rule would outvote every
  other signal.
- **Evidence is excerpted and escaped, never quoted raw.** It reaches logs, audit rows and CLI
  tables; a scanner that reproduced hostile text would hand the attacker a second channel into
  whoever is reading the report.
- **A malicious definition is quarantined whoever serves it**, trusted or not. A trusted server
  can be compromised, and that is precisely the case where auto-pinning must not apply.
- **An untrusted server's tools start quarantined even when the scan is clean.** That is what
  `trusted: false` buys. A clean scan is not a review.
- **The blocking threshold for output comes from the per-server action, not the verdict.** An
  untrusted server's flagged output is blocked at `suspicious`, because there is no user data to
  preserve and flagged content from a server we do not trust is most likely the attack; a
  trusted server's is wrapped and never blocked, because it is usually the user's own note
  quoting an instruction and swallowing it would lose their data.
- **Wrapped results keep their structured content, defanged.** Dropping it was the first
  implementation and it was a protocol bug: a tool that declares an `outputSchema` must return
  structured content, and a conforming client *raises* instead of accepting the result — so a
  wrapped answer became an error. Fencing it is not possible either, since the delimiters would
  have to go inside a schema-constrained field. The strings are stripped of hidden characters
  and the warning lives in `content`, which is what a model reads first.
- **The fence is escaped inside the content**, so hostile text cannot close its own delimiter
  and get out from under the warning.
- **DLP masks the arguments it flagged, by path.** `redact()` masks by key *name*, so a secret
  sent as `{"body": "<key>"}` was being written to the audit log verbatim — the very value the
  gateway had just refused to forward. The DLP scanner knows where it found one, so
  `ctx.redact_paths` masks those positions while `args_sha256` still covers the real arguments.
- **Generic high entropy is weighted so it cannot deny alone.** `files__write_file` content is
  legitimately arbitrary — a base64 image or a minified bundle is high-entropy and innocent — and
  weighting it to deny would make the gateway unusable for writing files, which is the kind of
  false positive that gets a security control switched off.
- **`DefinitionIntegrity` runs before `Policy`**, so a quarantined tool is refused for the same
  reason whoever asks, rather than reporting "no permission" to one caller and "quarantined" to
  another.
- **Quarantined tools are hidden from `tools/list` as well as refused.** For a poisoned tool the
  description *is* the attack, and a model that can see a tool keeps trying it.
- **The pin store keeps an in-memory view of what is quarantined**, rebuilt whenever a listing
  changes, so a `tools/call` never waits on a query to find out. A gateway that cannot read that
  view at startup **refuses to start**: coming up without it would serve every tool as though it
  had been approved.
- **`ToolPin.as_dict()` deliberately omits the definition.** A definition is attacker-controlled
  text and the pins listing has no reason to carry every poisoned description; only the diff
  endpoint asks for it, through `definitions_for_diff`, and renders both sides via `excerpt`.

## Phase 9 — human approvals

- **An approval is bound to (principal, tool, argument hash) and is single-use.** Those two
  properties are the whole security model, and both are checked *on use* rather than trusted
  from creation: an approval is looked up **by** its binding, so a different caller or different
  arguments simply do not find it. Three tests cover the replay cases — swapped arguments,
  different caller, second use.
- **Approving and consuming are compare-and-set updates, not read-then-write.** Two approvers
  clicking at the same instant produce exactly one decision and the loser is told so; eight
  concurrent retries of the same call consume one approval and forward one call.
- **Pending is not a denial.** A call nobody has decided returns `WARDEN_PENDING:approval` with
  the approval id, because nobody said no. A retry with the same arguments picks the decision
  up, and a retry *while still pending* reuses the same approval rather than filling the queue
  with duplicates.
- **A caller cannot approve their own request.** Without that, "needs approval" means "needs a
  second click from the same person", which is not a control. The UI hides the button as a
  courtesy and the store refuses it as the rule — there is a test that forges the form.
- **The approval stage sits after DLP and before the audit write-ahead.** After DLP, so a call
  carrying a secret is refused outright rather than put in front of a human to rubber-stamp.
  Before the write-ahead row, because a call waiting for a human has not started.
- **Approval lifecycle events go into the same hash-chained audit log.** Approvals are the one
  security decision a *human* makes; a reviewer asking "who let this through?" should not have
  to join two tables, and an approval trail that is not tamper-evident is barely a trail.
- **The consume event is emitted after its transaction commits.** The first version emitted from
  inside it, which wrote nothing: SQLite serialises writers on the file, so the audit insert
  deadlocked against the transaction still holding the write lock. On Postgres it would have
  read uncommitted state instead. Found because a test asserted the event existed.
- **Redis pub/sub is an optimisation, not a requirement.** A waiter polls every 250 ms and a
  published decision wakes it immediately; a pub/sub failure is suppressed and the poller takes
  over, so the feature degrades in latency rather than in correctness. A publish failure also
  must not fail the decision itself, which has its own test.
- **Progress notifications only when the client asked.** A `progressToken` is the client saying
  it wants them; without one the stage sees `None`. Sending is best effort — a client that has
  gone away must not turn a waiting approval into a failed request.
- **The UI exchanges the API key for a session cookie.** `HttpOnly`, `SameSite=Strict`,
  `Path=/approvals`, and `Secure` **only when the request actually arrived over https** (direct
  or via `X-Forwarded-Proto`). Setting `Secure` unconditionally makes the cookie unusable on
  plain-http localhost; not setting it in production puts the session on the wire.
- **A CSRF token on every POST, bound to the session and compared with `compare_digest`.**
  `SameSite=Strict` already covers the cross-site case in a modern browser; the token is the
  belt to those braces, and a missing or wrong one is a 403 rather than a silent no-op. A token
  from one session does not work in another.
- **Jinja autoescaping on, `StrictUndefined`, and no `|safe` anywhere** — with a test that reads
  every template and fails if one appears. Every value on that page is attacker-controlled: the
  tool name, the arguments, the scan evidence, the decision reason. All four have escaping tests.
- **Sessions live in memory, deliberately.** A single-node approval UI matches the rest of the
  phase, and the consequence — a restart signs admins out — is the safe direction.
- **`policies_allowing(..., prepend=True)` exists in the test harness because rule order
  matters.** The engine takes the first matching allow rule, so a test appending a
  `require_approval: false` rule for a tool the role could already call never reached it, and
  the call sat waiting for a human. The fix was in the test; the engine's first-match rule is
  the documented behaviour.

## Phase 10 — tracing and metrics

- **The SDK's OTel middleware is used, not replaced.** It already emits the root SERVER span
  with the current conventions (`mcp.method.name`, `gen_ai.operation.name`, `gen_ai.tool.name`)
  and already injects W3C `traceparent` into outbound `_meta`. Writing a second root span would
  have produced two spans per request with two sets of names for the same thing. The gateway adds
  what only it knows: a span per pipeline stage, and the security decision.
- **Span attributes are allowlisted, and the allowlist is enforced in one function.** Spans
  leave the trust boundary the audit log sits inside and nothing downstream redacts them, so
  `set_attributes` refuses anything not on the list and logs an error. The alternative — trusting
  every call site — breaks the first time someone adds an attribute to debug something.
- **`stage_span` is a no-op context manager when tracing is off**, which is the default. The
  check is on the provider class rather than a config flag, so it stays right if a provider is
  installed by something else.
- **The test fixture restores the *raw* `_TRACER_PROVIDER`, not `get_tracer_provider()`.** That
  accessor returns a proxy when nothing is set, and putting the proxy back into the slot it
  proxies makes every later lookup recurse until the stack ends. It did, in two tests.
- **`/metrics` is on an "optional authentication" list.** It was initially outside the auth
  middleware entirely, which meant an admin credential sent to it was never verified and the
  endpoint answered 403 to a valid admin key. The middleware now verifies a credential *if
  present* on such paths and leaves the requirement to the endpoint — and a credential that is
  present but wrong is still a 401, because silently ignoring one would hide a misconfigured
  scraper.
- **`tool` is a bounded label and `principal` is not a label.** An unknown tool name is recorded
  as the literal `unknown`; otherwise a caller could create a time series per invented name,
  which is a memory leak with a request interface. Per-caller numbers belong in the audit log.
- **Gauges are sampled at scrape time.** `warden_quarantined_tools` and
  `warden_pending_approvals` describe "right now", and keeping them in step from every code path
  that might change them is how gauges drift. A failure to count pending approvals logs a
  warning rather than failing the scrape.
- **The gateway uses its own `CollectorRegistry`, not the global default.** Two gateways in one
  test process would otherwise collide on metric names, and a test asserting that a counter
  moved needs to know which gateway moved it.
- **Grafana runs with anonymous viewer access in compose.** Local development only: the
  dashboard is read-only, carries no secrets, and a login prompt in front of a localhost
  dashboard is friction without security. Noted here so it is a decision rather than an
  oversight.
