# Threat model

What mcp-warden protects, from whom, and - for every mitigation - the test that would fail if
the mitigation stopped working. Test references are written `path::test_name`;
`tests/unit/test_threat_model_links.py` checks that every one of them exists, so this document
cannot quietly drift away from the code it describes.

Measured numbers (red-team scores, latency, soak drift) are not repeated here. They live in
`results/`, written by the scripts that measured them, and the README's results table is
generated from those files.

## Assets

| Asset | Why an attacker wants it |
| --- | --- |
| Upstream tool capability | `files__delete_file`, `notes_db__run_sql`: the ability to act on the user's data |
| Data reachable through a tool | note contents, sandboxed files, SQL rows |
| The model's instruction stream | the real target of tool poisoning and injection: the model, not the gateway |
| Callers' credentials | an API key or access token, reusable until revoked |
| The gateway's own secrets | the ES256 private keys, the database password, upstream credentials |
| Human approval decisions | an approval is the one place a person says yes to a destructive call |
| The audit log | an attacker who can edit it can make an attack unexplainable |
| Rate limits and budgets | exhausting them is a denial of service; evading them removes a brake |

## Trust boundaries

```
  browser / web page        UNTRUSTED: may try to reach a gateway on localhost (DNS rebinding)
        :
  MCP client (model)        UNTRUSTED input: arguments are attacker-influenced
        |  HTTP + Bearer
  ======|===================  boundary 1: transport limits, authentication, policy
   mcp-warden gateway        TRUSTED code; holds keys, writes the audit log
    |       |        |
    |       |  =====|=====    boundary 3: operator plane (admin API, approval UI, CLI)
    |       |     admin
    |  =====|========         boundary 4: backing stores (Postgres, Redis) - trusted, but may fail
    |    Postgres, Redis
  ==|=====================    boundary 2: upstreams are not trusted to tell the truth
   upstream MCP servers      UNTRUSTED output: descriptions and results are data, never instructions
```

At boundary 1 the question is *who is asking and for what*. At boundary 2 it is *is this answer
trying to steer the model*. Boundary 3 is where a human makes decisions, so it is attacked with
the techniques used against people: clickjacking, CSRF, fatigue. Boundary 4 is trusted for
integrity but not for availability, which is why every dependency failure has to deny.

## Attacker types

| Attacker | Capability assumed |
| --- | --- |
| Unauthenticated network caller | can reach `/mcp`, has no credential |
| Low-privilege credential holder | a valid `reader` key; wants editor or admin capability |
| Malicious or compromised upstream | controls its own tool descriptions and tool results; may change them later |
| Manipulated model | follows instructions it finds in tool output; calls tools with attacker-chosen arguments |
| Hostile web page | runs in the user's browser on the same machine as the gateway |
| Someone on the same network | can reach any port published on a non-loopback interface |
| Supply-chain attacker | controls a dependency release, a base image tag, or the classifier's model repository |
| Repository reader | wants a credential that was committed by accident |

## STRIDE by component

S = spoofing, T = tampering, R = repudiation, I = information disclosure, D = denial of service,
E = elevation of privilege.

### HTTP edge and transport

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| S | A web page drives a localhost gateway via DNS rebinding | `Host` allow-list on `/mcp`; foreign host is 421 | `tests/integration/test_gateway_hardening.py::test_a_request_for_a_foreign_host_name_is_refused` |
| S | A cross-origin page posts to `/mcp` from the user's browser | `Origin` allow-list; foreign origin is 403 | `tests/integration/test_gateway_hardening.py::test_a_cross_origin_browser_request_is_refused` |
| D | An oversized body exhausts memory before any check runs | 413 on declared or streamed size, before parsing | `tests/unit/test_http_limits.py::test_a_declared_oversize_body_is_refused_before_it_is_read`, `tests/unit/test_http_limits.py::test_an_undeclared_oversize_body_is_refused_while_streaming`, `tests/integration/test_gateway_hardening.py::test_an_oversized_mcp_body_is_refused_with_413` |
| D | A small `Content-Length` followed by a large body | bytes are counted, not trusted | `tests/unit/test_http_limits.py::test_a_lying_content_length_does_not_get_a_larger_body_through` |
| E | A JSON-RPC batch puts many calls behind one HTTP request and one audit decision | batches refused with JSON-RPC -32600 | `tests/unit/test_http_limits.py::test_a_batch_is_refused_with_a_json_rpc_error`, `tests/integration/test_gateway_hardening.py::test_a_json_rpc_batch_is_refused` |
| I | A log line is polluted through a client-supplied request id | only `[A-Za-z0-9_-]{1,64}` is accepted | `tests/unit/test_health.py::test_hostile_request_id_is_replaced` |
| I | Postgres or Redis reachable from the LAN | every compose port is published on 127.0.0.1 only | `docker-compose.yml` (reviewed, not unit-tested) |

### Authentication

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| S | No credential | 401 with `WWW-Authenticate` | `tests/integration/test_gateway_auth.py::test_no_credential_is_refused_at_the_transport` |
| S | Forged or tampered token | ES256 signature against published keys | `tests/unit/test_tokens.py::test_bad_signature_is_rejected` |
| S | `alg=none`, HS256-with-public-key, RS256 substitution | exactly one algorithm, checked before key load | `tests/unit/test_tokens.py::test_alg_none_is_rejected`, `tests/unit/test_tokens.py::test_hs256_signed_with_the_public_key_is_rejected`, `tests/unit/test_tokens.py::test_rs256_is_rejected` |
| S | A token minted for a different resource or issuer | `aud` and `iss` verified | `tests/unit/test_tokens.py::test_wrong_audience_is_rejected`, `tests/unit/test_tokens.py::test_wrong_issuer_is_rejected` |
| S | Two API keys sharing a lookup prefix | prefix narrows, constant-time hash compare decides | `tests/unit/test_api_keys.py::test_prefix_collision_does_not_let_one_key_pass_as_another` |
| S | A stolen credential after revocation | revoked keys and `jti`s refused, no restart | `tests/integration/test_gateway_auth.py::test_a_revoked_key_stops_working_without_a_restart`, `tests/unit/test_tokens.py::test_revoked_jti_is_rejected` |
| I | Credential stored, logged or echoed | hash-only storage; 401 body never echoes | `tests/unit/test_api_keys.py::test_the_raw_key_is_never_stored`, `tests/unit/test_auth_middleware.py::test_the_401_body_never_echoes_the_credential`, `tests/integration/test_gateway_auth.py::test_the_api_key_never_reaches_the_database_or_a_log` |
| I | Token passthrough: an upstream replays the caller's token | the caller's `Authorization` never leaves the gateway | `tests/integration/test_gateway_auth.py::test_the_client_credential_is_never_forwarded_to_an_upstream` |
| I | A stdio upstream inherits `DATABASE_URL`, a private index token, etc. | minimal environment plus a named allow-list of `uv` launcher settings | `tests/integration/test_gateway_auth.py::test_stdio_upstreams_do_not_inherit_the_gateways_credentials`, `tests/unit/test_upstream_manager.py::test_nothing_outside_the_allowlist_reaches_an_upstream` |
| D | Credential store or revocation store unreachable | 401 / reject, fail closed | `tests/unit/test_auth_middleware.py::test_a_backend_failure_fails_closed`, `tests/unit/test_tokens.py::test_a_failing_revocation_store_fails_closed` |

### Policy

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| E | A reader calls a write or delete tool | deny by default; roles grant explicitly | `tests/integration/test_gateway_policy.py::test_a_reader_cannot_see_or_call_the_delete_tool`, `tests/unit/test_policy_engine.py::test_a_reader_is_never_granted_a_write_or_delete_tool` |
| E | An unknown tool or unknown role slips through | unknown tool is destructive; unknown role grants nothing | `tests/unit/test_policy_engine.py::test_an_unknown_tool_is_treated_as_destructive`, `tests/unit/test_policy_engine.py::test_unknown_roles_never_grant_the_destructive_tool` |
| E | Path traversal through an allowed tool (`../`, percent-encoding) | `starts_with` compares normalised whole segments | `tests/integration/test_gateway_policy.py::test_an_argument_constraint_blocks_traversal_at_the_gateway`, `tests/unit/test_policy_engine.py::test_no_path_an_editor_can_write_ever_escapes_the_root` |
| E | A glob in one server's rule matches another server's tools | glob never crosses the `__` separator | `tests/unit/test_policy_engine.py::test_a_pattern_that_does_not_name_a_server_is_rejected` |
| E | An omitted argument lets the upstream's own default run unchecked | the pinned schema's default is filled *before* policy and forwarded as checked | `tests/integration/test_gateway_defaults.py::test_what_the_upstream_receives_is_what_the_gateway_checked`, `tests/unit/test_policy_defaults.py::test_the_stage_sits_between_integrity_and_policy` |
| E | An upstream declares a default that violates the operator's constraint | the filled value is checked like a caller's; refused, never forwarded | `tests/integration/test_gateway_defaults.py::test_a_default_that_breaks_a_constraint_is_refused_and_never_forwarded` |
| T | A rug pull changes only a default | the definition hash covers the schema, so the tool is quarantined first | `tests/unit/test_policy_defaults.py::test_changing_only_a_default_changes_the_pin` |
| D | A schema-conforming call that omits an optional argument is refused | defaults filled, so the constraint sees a value | `tests/integration/test_gateway_defaults.py::test_list_files_without_a_path_is_allowed` |
| T | A broken policy reload leaves the gateway open | the old policy stays in force | `tests/integration/test_gateway_policy.py::test_a_broken_reload_is_rejected_and_the_old_policy_still_enforces` |
| I | `tools/list` reveals tools the caller cannot use | listing is filtered by the same policy | `tests/integration/test_gateway_policy.py::test_each_role_sees_a_different_tool_list` |

### Rate limits and budgets

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| D | One caller floods a tool | atomic token bucket in one Redis Lua script | `tests/integration/test_gateway_limits.py::test_a_burst_past_the_bucket_is_denied`, `tests/integration/test_gateway_limits.py::test_fifty_concurrent_calls_against_real_redis_allow_exactly_the_capacity` |
| D | A destructive spree within the general budget | separate daily destructive budget | `tests/integration/test_gateway_limits.py::test_the_daily_destructive_budget_is_separate` |
| D | A huge result floods the model's context | denied, never truncated | `tests/integration/test_gateway_limits.py::test_an_oversized_result_is_denied_not_truncated` |
| E | Redis down turns limits off | denies every call | `tests/integration/test_gateway_limits.py::test_the_limiter_being_down_denies_every_call` |
| E | Redis accepts the connection and stops answering, hanging requests | explicit 2 s socket timeouts; the limiter denies | `tests/integration/test_hung_dependencies.py::test_a_silent_redis_makes_the_limiter_deny_rather_than_hang` |

### Definition integrity (pinning and quarantine)

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| T | Tool poisoning: hidden instructions in a description | definition scan; malicious tools quarantined and hidden | `tests/integration/test_gateway_scanning.py::test_the_poisoned_tool_is_quarantined_as_malicious_not_merely_unreviewed` |
| T | Rug pull: an approved definition changes later | SHA-256 pin per tool, checked on every refresh | `tests/integration/test_gateway_scanning.py::test_a_rug_pull_quarantines_the_tool_after_the_definition_changes` |
| S | Tool shadowing: a tool claims to replace another server's | cross-tool reference rules | `tests/integration/test_gateway_scanning.py::test_the_shadowing_tool_is_flagged_for_claiming_to_replace_another` |
| E | An unreviewed third-party server's tools are usable at once | `trusted: false` quarantines everything until an admin approves | `tests/integration/test_gateway_scanning.py::test_an_untrusted_servers_tools_all_start_quarantined` |
| E | A quarantined tool called by name, bypassing the listing | denied at call time | `tests/integration/test_gateway_scanning.py::test_a_quarantined_tool_is_denied_when_called_by_name` |
| I | Scan evidence re-emits the hidden characters it found | evidence is made visible, never reproduced | `tests/integration/test_gateway_scanning.py::test_the_evidence_never_reproduces_hidden_characters` |
| T | The pin table cannot be read, so every definition looks new | the gateway refuses to start | `tests/integration/test_gateway_audit.py::test_the_gateway_refuses_to_start_when_it_cannot_read_the_pin_table` |

### Argument DLP

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| I | A manipulated model sends a credential to an exfiltration tool | DLP before forwarding; `WARDEN_DENIED:dlp`; nothing reaches the sink | `tests/integration/test_gateway_scanning.py::test_a_secret_in_an_argument_is_refused_and_the_sink_records_nothing`, `tests/integration/test_gateway_scanning.py::test_each_secret_format_is_refused` |
| I | The refused secret is then written to the audit log | DLP-found paths masked by position, plus a hash | `tests/unit/test_audit_log.py::test_a_canary_in_the_arguments_reaches_no_column` |
| D | DLP refuses ordinary data | specific formats only; a base64 blob alone is not a secret | `tests/integration/test_gateway_scanning.py::test_ordinary_arguments_are_not_refused_by_dlp`, `tests/integration/test_gateway_scanning.py::test_a_base64_blob_alone_is_not_treated_as_a_secret` |

### Human approval

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| E | A destructive call runs without a human | pending until approved; never forwarded when denied | `tests/integration/test_gateway_approvals.py::test_a_destructive_call_waits_and_runs_once_when_approved`, `tests/integration/test_gateway_approvals.py::test_a_denied_call_is_refused_and_never_forwarded` |
| T | An approval for one call reused for different arguments, another caller or twice | bound to principal, tool and argument hash; single use by compare-and-set | `tests/integration/test_gateway_approvals.py::test_an_approval_cannot_be_reused_for_different_arguments`, `tests/integration/test_gateway_approvals.py::test_an_approval_cannot_be_used_by_a_different_caller`, `tests/unit/test_approval_store.py::test_an_approval_is_single_use` |
| E | The requester approves their own call | refused, even with a forged form | `tests/integration/test_gateway_approvals.py::test_the_requester_cannot_approve_their_own_call`, `tests/unit/test_approval_ui.py::test_self_approval_is_refused_even_if_the_form_is_forged` |
| T | Two approvers race; one call runs twice | one decision, one forwarded call | `tests/integration/test_gateway_approvals.py::test_two_approvers_at_once_produce_one_forwarded_call` |
| S | CSRF against the approval form | `SameSite=Strict` cookie plus a session-bound token | `tests/unit/test_approval_ui.py::test_a_post_without_a_csrf_token_is_refused`, `tests/unit/test_approval_ui.py::test_one_sessions_token_does_not_work_for_another` |
| T | Stored XSS through a tool name, argument or reason | autoescape, no `|safe`, strict CSP with no inline script | `tests/unit/test_approval_ui.py::test_hostile_argument_values_are_escaped`, `tests/unit/test_approval_headers.py::test_the_policy_forbids_inline_script_and_style` |
| S | Clickjacking: the approve button inside another site's frame | `frame-ancestors 'none'` and `X-Frame-Options: DENY` | `tests/unit/test_approval_headers.py::test_framing_is_refused_by_both_mechanisms`, `tests/integration/test_gateway_hardening.py::test_the_approval_page_sends_its_security_headers` |
| T | A compromised CDN serves different JavaScript | exact-URL `script-src` plus SRI hash | `tests/unit/test_approval_headers.py::test_the_script_tag_matches_the_policy_and_carries_an_integrity_hash` |
| I | The admin key ends up in the page, a URL or the cache | exchanged once for an HttpOnly cookie; `Cache-Control: no-store` | `tests/unit/test_approval_ui.py::test_the_key_never_appears_in_the_page`, `tests/unit/test_approval_ui.py::test_a_valid_admin_key_sets_a_hardened_session_cookie` |
| R | "Who let this through?" has no answer | the full lifecycle is in the hash-chained audit log | `tests/integration/test_gateway_approvals.py::test_the_whole_approval_lifecycle_is_in_the_audit_log` |

### Upstream forwarding

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| D | A slow upstream ties up the gateway | per-upstream timeout | `tests/integration/test_gateway_proxy.py::test_slow_upstream_hits_the_timeout` |
| D | One dead upstream takes the others with it | independent connections; only its tools disappear | `tests/integration/test_gateway_proxy.py::test_killing_one_upstream_removes_only_its_tools` |
| I | An upstream exception's text leaks internals to the caller | mapped to a reason code | `tests/unit/test_proxy_stages.py::test_forward_does_not_leak_the_upstream_exception_text` |
| E | The malicious test server is capable of real harm | static scan forbids I/O and process APIs in its source | `tests/unit/test_evil_server_is_inert.py::test_no_forbidden_imports` |

### Output scanning and the classifier

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| T | Indirect injection in a tool result | blocked from untrusted servers, fenced and labelled from trusted ones | `tests/integration/test_gateway_scanning.py::test_every_injection_variant_in_output_is_blocked`, `tests/integration/test_gateway_scanning.py::test_a_trusted_servers_flagged_output_is_wrapped_not_blocked` |
| D | The classifier crashes or times out and output flows unscanned | an error blocks untrusted output | `tests/unit/test_classifier.py::test_a_classifier_error_blocks_output_from_an_untrusted_server`, `tests/unit/test_classifier.py::test_a_timeout_is_an_error_not_a_zero` |
| D | A classifier false positive quarantines a legitimate tool | the classifier alone cannot quarantine | `tests/unit/test_classifier.py::test_a_classifier_error_does_not_quarantine_a_tool`, `tests/unit/test_scan_dataset.py::test_a_classifier_hit_alone_can_never_block_or_quarantine` |
| T | New weights pushed to the model repository under the same name | pinned to a 40-hex commit; safetensors only | `tests/unit/test_classifier.py::test_loading_pins_the_revision_and_refuses_pickle_weights`, `tests/unit/test_classifier.py::test_a_mutable_or_abbreviated_revision_is_a_config_error` |

### Audit log

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| R | A call happens with no record | write-ahead row before forwarding; unwritable log denies | `tests/integration/test_gateway_audit.py::test_an_unwritable_audit_log_denies_the_call_and_forwards_nothing` |
| R | Denials are not recorded, so probing is invisible | every denial leaves a row, including unauthenticated ones | `tests/integration/test_gateway_audit.py::test_a_policy_denial_leaves_one_denied_row_and_never_forwards`, `tests/unit/test_audit_log.py::test_an_unauthenticated_denial_still_leaves_a_row` |
| T | A row is edited, deleted, reordered or forged | SHA-256 hash chain; `warden audit verify` names the break | `tests/integration/test_gateway_audit.py::test_verify_detects_an_edited_row`, `tests/integration/test_gateway_audit.py::test_verify_detects_a_deleted_row`, `tests/integration/test_gateway_audit.py::test_verify_detects_a_reordered_pair`, `tests/integration/test_gateway_audit.py::test_verify_detects_a_forged_inserted_row` |
| T | Concurrent writers fork the chain | in-process lock plus a Postgres advisory lock | `tests/integration/test_audit_postgres.py::test_two_independent_writers_do_not_fork_the_chain` |
| T | The gateway's database role rewrites history | `warden db harden`: SELECT and INSERT only | `tests/integration/test_audit_postgres.py::test_the_audit_table_is_append_only_for_a_non_owner_member` |
| I | Secrets stored in the log | key-name redaction, DLP path masking, argument hash only | `tests/integration/test_gateway_audit.py::test_no_credential_or_canary_reaches_any_audit_column` |
| E | `harden` is given a hostile role name | identifiers restricted to `[A-Za-z0-9_]` before any SQL | `tests/integration/test_audit_postgres.py::test_harden_rejects_a_role_name_that_is_not_a_plain_identifier` |

### Admin API, CLI and telemetry

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| E | A non-admin reaches `/admin` | admin role required | `tests/integration/test_gateway_policy.py::test_admin_endpoints_require_the_admin_role` |
| I | `/metrics` tells an attacker which tools exist and are quarantined | loopback, a named scraper network, or admin only | `tests/integration/test_gateway_telemetry.py::test_metrics_require_the_admin_role_when_loopback_is_not_allowed`, `tests/integration/test_gateway_telemetry.py::test_a_scraper_network_that_does_not_contain_the_client_grants_nothing` |
| E | A scraper allow-list that admits everyone | `0.0.0.0/0` and `::/0` refused | `tests/unit/test_config.py::test_a_metrics_network_that_allows_everyone_is_refused` |
| I | Arguments or credentials in spans or metric labels | span attribute allow-list; no principal label | `tests/unit/test_telemetry.py::test_no_argument_or_credential_ever_reaches_a_span`, `tests/unit/test_telemetry.py::test_no_metric_is_labelled_by_principal` |
| D | An attacker invents tool names to explode metric cardinality | unknown tools collapse to one label | `tests/integration/test_gateway_telemetry.py::test_an_invented_tool_name_does_not_create_a_time_series` |

### Build and supply chain

| | Threat | Mitigation | Proof |
| --- | --- | --- | --- |
| T | A dependency release with a known vulnerability | `uv.lock` pins every version and hash; `make security` runs pip-audit | `make security` (see `docs/decisions.md`, Phase 13) |
| T | Trojan-source: invisible or bidi characters in our own source | none allowed in any text file; written as `\u` escapes | `tests/unit/test_source_hygiene.py::test_no_text_file_contains_a_literal_format_character` |
| T | A base image re-pushed under the same tag | `Dockerfile` pins tag and digest | `Dockerfile` (reviewed, not unit-tested) |
| E | A container escape is easier as root, with capabilities, on a writable root | uid 10001, `cap_drop: ALL`, `no-new-privileges`, `read_only: true` | `docker-compose.yml` (verified by running it; see `docs/decisions.md`) |
| I | Secrets in the repository | `.env` gitignored; keys directory gitignored; `detect-private-key` pre-commit hook | `tests/integration/test_gateway_auth.py::test_the_api_key_never_reaches_the_database_or_a_log` |

## Fail-closed matrix

Hard rule 1, one line per dependency:

| When this fails | The call is | Proof |
| --- | --- | --- |
| Redis (limiter) refuses connections | denied | `tests/integration/test_gateway_limits.py::test_the_limiter_being_down_denies_every_call` |
| Redis hangs | denied within the socket timeout | `tests/integration/test_hung_dependencies.py::test_a_silent_redis_makes_the_limiter_deny_rather_than_hang` |
| Postgres (audit log) unwritable | denied, nothing forwarded | `tests/integration/test_gateway_audit.py::test_an_unwritable_audit_log_denies_the_call_and_forwards_nothing` |
| Credential store | 401 | `tests/unit/test_auth_middleware.py::test_a_backend_failure_fails_closed` |
| Revocation store | token rejected | `tests/unit/test_tokens.py::test_a_failing_revocation_store_fails_closed` |
| Classifier crashes or times out | untrusted output blocked | `tests/unit/test_classifier.py::test_a_classifier_error_blocks_output_from_an_untrusted_server` |
| Any pipeline stage raises | `WARDEN_DENIED:internal` | `tests/unit/test_pipeline.py::test_a_stage_that_raises_denies_rather_than_allowing` |
| Upstream down | `WARDEN_DENIED` with a reason code | `tests/unit/test_proxy_stages.py::test_forward_denies_when_the_upstream_is_down` |
| Policy file broken on reload | previous policy keeps enforcing | `tests/unit/test_policy_engine.py::test_a_broken_file_keeps_the_old_policy_in_force` |
| Policy file missing at start | the gateway does not start | `tests/unit/test_policy_engine.py::test_a_missing_file_at_startup_is_a_hard_error` |

## Known gaps

Stated rather than implied. Each is a real limit of v0.1.0, not a hypothetical.

- **Classifier evasion, and the classifier's own weakness.** On the project's labelled set the
  model flags ordinary security prose as confidently as real injections and adds no detection
  over the rules on the red-team suite (see `results/redteam-*.md` and the Phase 8 entry in
  `docs/decisions.md`). It therefore ships off and cannot block or quarantine alone. The rules
  are specific by design: a novel phrasing that matches no rule gets through. Policy,
  approvals and the audit log are the layers that assume this one will sometimes fail.
- **Approval fatigue.** The gateway proves an approval is needed, bound to the exact arguments
  and single-use. It cannot prove a human read them. A queue that asks too often trains people
  to click approve.
- **No external OAuth server.** `warden token create` is a development issuer. The gateway
  publishes RFC 9728 metadata naming itself in `authorization_servers` but serves none of the
  authorization-server endpoints, so an OAuth-capable client dies at client registration
  (observed with the MCP Inspector; see `docs/clients.md`). Clients must be given a
  pre-issued key or token.
- **Single node.** Approval sessions live in memory, and the in-process audit lock is backed by
  a Postgres advisory lock only on Postgres. Two gateways would need shared sessions and
  Postgres; SQLite is single-writer by definition.
- **Stdio upstreams are trusted at the process level.** A stdio upstream runs as a child of the
  gateway, as the same user, with the gateway's filesystem view. The gateway constrains what
  the *model* can ask it to do; it does not sandbox what the upstream process itself does. An
  untrusted upstream belongs behind Streamable HTTP in its own container.
- **The hash chain detects partial tampering, not a wholesale rebuild.** Truncating the tail
  also leaves a consistent chain. `warden audit verify` prints the head hash so it can be
  pinned outside the gateway; doing that pinning is not implemented.
- **`redact()` masks by key name.** A secret DLP does not recognise, sent under an innocent
  key, is stored redacted-by-name only.
- **Wrapping is advisory.** A model that ignores the warning banner and follows fenced text
  anyway is outside the gateway's control; that is why destructive tools also need approval.
- **Multi-turn manipulation.** Each red-team case is one or a few calls. An attack spread over a
  long conversation, each call individually innocuous, would pass.
- **A compromised gateway.** Everything above assumes the gateway's process and keys are
  intact. The audit log is tamper-*evident*, not tamper-proof.
- **TLS.** Assumed to be terminated in front of the gateway. Compose publishes plain HTTP on
  loopback only.
