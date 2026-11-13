# Threat model

A full STRIDE table and the measured "known gaps" list land in Phase 13. This file grows one
section per security phase, so each claim is written down next to the tests that prove it.

## Assets

| Asset | Why an attacker wants it |
| --- | --- |
| Upstream tool capability | `files__delete_file`, `notes_db__run_sql`: the ability to act on the user's data |
| Data reachable through a tool | note contents, sandboxed files, SQL rows |
| The caller's credential | an API key or access token, reusable until revoked |
| The gateway's own secrets | the ES256 private keys, the database password |
| The model's instruction stream | the real target of tool poisoning and injection: the model, not the gateway |
| The audit log | an attacker who can edit it can make an attack unexplainable |

## Trust boundaries

```
  MCP client (model)        UNTRUSTED input: arguments are attacker-influenced
        |  HTTP + Bearer
  ======|=================  boundary 1: authentication and policy
   mcp-warden gateway       TRUSTED code, holds the keys and the audit log
        |  stdio / HTTP
  ======|=================  boundary 2: upstreams are not trusted to tell the truth
   upstream MCP servers     UNTRUSTED output: descriptions and results are data, never instructions
```

Both boundaries matter and they fail differently. At boundary 1 the question is *who is asking*.
At boundary 2 the question is *is this answer trying to steer the model*. A gateway that only
guards boundary 1 is a firewall with a hole in the back.

## Attacker types

| Attacker | Capability assumed |
| --- | --- |
| Unauthenticated network caller | can reach `/mcp`, has no credential |
| Holder of a low-privilege credential | a valid `reader` key, wants editor or admin capability |
| A compromised or malicious upstream server | controls its own tool descriptions and tool results |
| A manipulated model | will follow instructions it finds in tool output, and will call tools |
| Someone who can read the repository | wants a credential that was committed by accident |

## Phase 4 — authentication

### What is enforced

- `/mcp` and `/admin` require `Authorization: Bearer <credential>`. A missing or invalid
  credential is **HTTP 401** with a `WWW-Authenticate` header naming the protected-resource
  metadata document — a protocol problem, not a tool result.
- Two credential types: `wdn_`-prefixed API keys, and ES256 JWTs.
- API keys are stored as **SHA-256 hash plus an 8-character prefix**. The prefix only narrows
  the lookup; a full `hmac.compare_digest` on the hash decides. Two keys sharing a prefix
  authenticate only as themselves.
- Tokens are verified with **ES256 only**. PyJWT is given exactly one algorithm and the `alg`
  header is checked before any key is loaded.
- Required claims: `iss`, `aud`, `sub`, `roles`, `iat`, `nbf`, `exp`, `jti`. The audience is the
  gateway's own resource URL, so a token minted for a different MCP server is refused.
- 30 seconds of clock skew is allowed, in both directions.
- Two signing keys are active at once. A rotation adds a key and keeps the previous one
  verifying; a retired key verifies nothing.
- Revoked `jti` values live in Redis with a TTL equal to the token's remaining lifetime.
- The pipeline's `Authenticate` stage re-asserts that a principal arrived, and denies with
  `WARDEN_DENIED:auth` if one did not. A credential with no roles is also refused: it could
  never be allowed anything, so accepting it only creates a confusing audit trail.

### NO TOKEN PASSTHROUGH

**The client's credential is never forwarded to an upstream.** The gateway is a separate MCP
client; it builds its upstream connections from `config/servers.yaml` alone, and an upstream's
own credentials come from that file's `env`/`${VAR}` references, resolved from the gateway's
environment at load time. A missing variable is a load-time error, not an empty string.

This matters because token passthrough is the standard way a proxy turns one compromised
upstream into a full account takeover: an upstream that receives the caller's bearer token can
replay it against the gateway, against the real authorization server, and against any other
resource that accepts the same audience. Proven by
`tests/integration/test_gateway_auth.py::test_the_client_credential_is_never_forwarded_to_an_upstream`,
which puts a header-recording MCP server behind the gateway and asserts no `Authorization`
header arrives.

A stdio upstream also does not inherit the gateway's environment wholesale: the SDK passes only
a small allowlist of variables plus whatever `servers.yaml` sets, so `DATABASE_URL` and friends
do not reach a child process.

### Attacks covered, and the test that proves it

| Attack | Result | Test |
| --- | --- | --- |
| No credential | 401 | `test_no_credential_is_refused_at_the_transport` |
| Wrong scheme (Basic, Digest) | 401 | `test_malformed_or_wrong_scheme_is_401` |
| Forged token, unknown signer | rejected | `test_bad_signature_is_rejected` |
| `alg=none` | rejected | `test_alg_none_is_rejected` |
| HS256 signed with the published public key | rejected | `test_hs256_signed_with_the_public_key_is_rejected` |
| RS256 substituted for ES256 | rejected | `test_rs256_is_rejected` |
| Expired / not-yet-valid token | rejected | `test_expired_token_is_rejected`, `test_not_yet_valid_token_is_rejected` |
| Token for another resource | rejected | `test_wrong_audience_is_rejected` |
| Token from another issuer | rejected | `test_wrong_issuer_is_rejected` |
| Token signed by a retired key | rejected | `test_a_retired_kid_is_rejected` |
| Revoked token | rejected | `test_revoked_jti_is_rejected` |
| Revoked API key | 401, no restart needed | `test_a_revoked_key_stops_working_without_a_restart` |
| Credential store unreachable | 401, fails closed | `test_a_backend_failure_fails_closed` |
| Revocation store unreachable | rejected, fails closed | `test_a_failing_revocation_store_fails_closed` |
| Credential echoed back to the caller | never | `test_the_401_body_never_echoes_the_credential` |
| Credential written to a log or the database | never | `test_the_api_key_never_reaches_the_database_or_a_log` |
| Credential forwarded upstream | never | `test_the_client_credential_is_never_forwarded_to_an_upstream` |

### Out of scope, deliberately

- **An external OAuth 2.1 authorization server.** `warden token create` is a development
  issuer. A real deployment points `authorization_servers` in
  `/.well-known/oauth-protected-resource` at a real server and stops issuing its own tokens;
  the verification path does not change, because it already verifies `iss`, `aud` and `kid`
  against a published JWKS.
- **Mutual TLS, and TLS termination in general.** Assumed to be handled by whatever fronts the
  gateway. The transport layer does enforce DNS-rebinding protection via an allowed-hosts list,
  so a web page cannot drive a gateway bound to localhost.
- **Hardware-backed key storage.** The ES256 private keys are files with mode `0600` in a
  gitignored directory, with `detect-private-key` in pre-commit as the backstop against a
  commit. A production deployment should use a KMS or a secret store instead.

## Phase 8 — tool poisoning, rug pulls, injection and exfiltration

This is the boundary-2 half of the model: upstream descriptions and results are data, never
instructions.

### What is enforced

| Attack | Control | Result |
| --- | --- | --- |
| Tool poisoning (hidden instructions in a description) | definition scan on every refresh | quarantined, hidden from `tools/list`, `WARDEN_DENIED:quarantined` |
| Rug pull (approved definition changes later) | SHA-256 pin per tool, compared on every refresh | quarantined, with a diff for the operator |
| Tool shadowing (claims to replace another server's tool) | cross-tool reference rules | quarantined |
| Indirect prompt injection in a result | output scan; block for untrusted, wrap for trusted | `WARDEN_DENIED:injection`, or fenced and labelled |
| Encoded injection (base64, zero-width, bidi, non-English) | one decode layer, NFKC folding, invisible stripping | detected by the same rules |
| Exfiltration through an argument | DLP scan before forwarding | `WARDEN_DENIED:dlp`, never forwarded |
| An unreviewed third-party server | `trusted: false` | every tool quarantined until an admin approves |

### Known gaps, stated rather than implied

- **The classifier is weak on structural attacks.** Measured at 69.6% detection with 4.3% false
  positives on the project's own labelled set; it misses every shadowing and exfiltration case.
  It is one weighted signal and cannot block or quarantine on its own. See
  `docs/decisions.md` for the full table and the threshold sweep.
- **A novel phrasing that matches no rule and scores below the classifier threshold gets
  through.** The rules are specific by design, which is what keeps false positives near zero,
  and the cost is that they are not a general injection detector. Policy, approvals and the
  audit log are the layers that assume this one will sometimes fail.
- **`redact()` masks by key name.** A secret sent under an innocent key reaches the audit log
  unless DLP flags it — which is why DLP marks the paths it found and the audit writer masks
  them by position. A secret DLP does not recognise is still stored redacted-by-name only.
- **Wrapping is advisory.** A model that ignores the warning banner and follows the fenced text
  anyway is not something the gateway can prevent; that is why destructive tools need an
  approval as well.
- **The hash chain detects partial tampering, not a wholesale rebuild**, and truncating the tail
  leaves a consistent chain. `warden audit verify` prints the head hash so it can be pinned
  outside the gateway; doing that pinning is not implemented.
- **SQLite has no roles**, so the append-only property of the audit log rests on the hash chain
  alone there. `warden db harden` makes it a grant on Postgres.
