# Connecting a client

Every step below was run against this gateway on macOS on 2026-11-14, with the versions named.
Where a step comes from a vendor's documentation and was **not** run here, it says so in the
step itself. That distinction is the point of this page: a connection guide full of plausible
but untested instructions wastes more time than no guide at all.

```
MCP Inspector CLI   verified here
MCP Inspector web   verified here, including what does NOT work
Cursor              config format from Cursor's docs; not driven here
Claude Desktop      cannot reach a localhost gateway at all - see below
```

## Before any client

```bash
make up                 # postgres + redis
uv run warden db upgrade
uv run warden keys init-jwt
uv run warden serve     # http://127.0.0.1:8080/mcp
```

Mint a credential. An API key does not expire and suits a desktop client; a token expires in
15 minutes by default and suits a script.

```bash
uv run warden keys create --user you --roles editor --label "cursor on my laptop"
```

```bash
uv run warden token create --user you --roles editor --ttl 3600
```

Both are sent the same way, which is the only thing a client has to get right:

```
Authorization: Bearer <the key or token>
```

The secret is printed once. Keep it in your password manager or shell environment, never in a
file you commit - `.cursor/mcp.json` and `claude_desktop_config.json` are both files people
commit by accident.

### The URL has to match `WARDEN_RESOURCE_URL`

`.env` sets `WARDEN_RESOURCE_URL=http://localhost:8080/mcp`, and the gateway publishes that
string as its resource identifier. A client that connects to `http://127.0.0.1:8080/mcp`
instead is pointing at the same socket under a different name, and an OAuth-aware client
checks the two against each other. The Inspector rejected exactly this:

```
Protected resource http://localhost:8080/mcp does not match expected http://127.0.0.1:8080/mcp (or origin)
```

Use one spelling everywhere. These docs use `localhost`, matching the shipped `.env.example`.

## MCP Inspector - CLI

Verified with `@modelcontextprotocol/inspector` 2.13.0 on Node 26.5.0. This is the quickest way
to see the gateway working, and the only client here that needs no configuration file.

List the tools your role is allowed to see:

```bash
npx -y @modelcontextprotocol/inspector --cli http://localhost:8080/mcp --transport http --method tools/list --header "Authorization: Bearer $WARDEN_KEY"
```

With the shipped `policies.yaml` and the `editor` role, that returned ten tools:

```
files__delete_file files__list_files files__read_file files__write_file
notes_db__create_note notes_db__delete_note notes_db__get_note notes_db__list_notes
notes_db__run_sql notes_db__search_notes
```

Note what is *not* there: the `evil` server's tools. `tools/list` is filtered by policy and by
quarantine state, so a tool you are not allowed to call is not a tool you are shown.

Call one:

```bash
npx -y @modelcontextprotocol/inspector --cli http://localhost:8080/mcp --transport http --method tools/call --tool-name notes_db__list_notes --header "Authorization: Bearer $WARDEN_KEY"
```

### Seeing a denial

This is the useful part. Ask for a file outside the sandbox:

```bash
npx -y @modelcontextprotocol/inspector --cli http://localhost:8080/mcp --transport http --method tools/call --tool-name files__read_file --tool-arg 'path=../../etc/passwd' --header "Authorization: Bearer $WARDEN_KEY"
```

The gateway answered, verbatim:

```json
{
  "content": [
    {
      "type": "text",
      "text": "WARDEN_DENIED:policy: the arguments do not satisfy the policy: argument 'path' must be inside '.' (checked after normalisation)"
    }
  ],
  "structuredContent": {
    "error": "WARDEN_DENIED:policy",
    "reason": "the arguments do not satisfy the policy: argument 'path' must be inside '.' (checked after normalisation)",
    "request_id": "a0a110a70e13464496ed65d09a252c79",
    "matched_rule": "editor-files-read"
  },
  "isError": true
}
```

That is hard rule 4 as a client sees it: a normal tool result with `isError: true`, a machine
readable reason code, the rule that decided it, and a request id you can look up:

```bash
uv run warden audit tail --request-id a0a110a70e13464496ed65d09a252c79
```

A denial from the *upstream* looks different on purpose - no `WARDEN_` code, because the
gateway allowed the call and the tool itself refused:

```
Error executing tool run_sql: query rejected: 'delete' is not allowed in a read-only query
```

### Exit codes

Observed, not quoted from the documentation:

| What happened | Exit |
| --- | --- |
| `tools/list` succeeded | `0` |
| No `Authorization` header at all | `3` |
| A call the gateway denied (`isError: true`) | `5` |

Exit `5` covers both a gateway denial and an upstream error, so a script that needs to tell
them apart has to read `structuredContent.error`, not the exit code.

`--strict` passed against the gateway's listing (exit `0`), meaning every tool schema the
gateway republishes is portable by the Inspector's check.

## MCP Inspector - web UI

```bash
make inspector
```

The command prints a URL carrying a one-time token and, unless `MCP_AUTO_OPEN_ENABLED=false`,
opens it. Add the gateway from the UI's server list, with `http://localhost:8080/mcp`,
transport **Streamable HTTP**, and an `Authorization` header.

**What does not work, verified here:** launching the web UI with `--server-url` makes a
*read-only session* - the UI says so - and a read-only server cannot have a header added to it.
Without a header the Inspector falls back to OAuth, and the gateway is not an OAuth
authorization server, so the connection fails at:

```
Dynamic Client Registration rejected (HTTP 404): Not Found
```

That is not a gateway fault and not something a retry fixes. Either add the server from inside
the UI, or launch with `--config` pointing at a file that carries the header. The `--config`
route is documented by the Inspector and was **not** run here.

### A note on the gateway's OAuth metadata

The gateway implements the resource-server half of the MCP authorization spec and none of the
authorization-server half. It publishes protected-resource metadata, verified at both
locations RFC 9728 allows:

```bash
curl http://localhost:8080/.well-known/oauth-protected-resource/mcp   # 200
curl http://localhost:8080/.well-known/oauth-protected-resource       # 200
```

and its 401 points a client at the first of those:

```
www-authenticate: Bearer realm="mcp-warden", resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp"
```

But `authorization_servers` in that document names the gateway itself, and the gateway serves
no `/.well-known/oauth-authorization-server`, no `/authorize`, no `/token` and no `/register`
(all 404, checked). A client that tries the full OAuth flow therefore gets as far as client
registration and stops. **Give every client a pre-issued key or token in a header.** This
limitation is recorded in `docs/decisions.md`.

## Cursor

Cursor reads `~/.cursor/mcp.json` (every project) or `.cursor/mcp.json` (one project), and
identifies a remote server by the presence of `url`. From Cursor's own documentation - the
format below is theirs, and **Cursor was not driven here**, so treat this as the shape to try
rather than a transcript:

```json
{
  "mcpServers": {
    "warden": {
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer ${env:WARDEN_KEY}"
      }
    }
  }
}
```

Cursor interpolates `${env:NAME}` in `url` and `headers`, so the key can live in your shell
profile rather than in the file. `envFile` is stdio-only and will not help here. Put
`.cursor/mcp.json` in `.gitignore` if you ever inline the key instead.

The gateway's own behaviour on that path *is* verified: it is the same Streamable HTTP endpoint
with the same bearer header the Inspector used above.

## Claude Desktop

**A custom connector cannot reach this gateway on localhost.** Claude Desktop's remote
connectors are opened from Anthropic's infrastructure, not from your machine, so
`http://localhost:8080/mcp` is not a URL it can resolve. This is per Anthropic's current
documentation; it is also why there is no verified transcript for it here.

Two ways round it, neither run here:

1. **A stdio bridge.** Claude Desktop's local server config spawns a process, and
   `mcp-remote` translates stdio to Streamable HTTP with a header. This is the documented
   approach for exactly this situation.
2. **Expose the gateway.** Put it behind a public HTTPS name you control and add it as a
   remote connector. Do not do this with the dev defaults: the shipped `.env.example` password
   is a placeholder, and `warden db harden` exists for a reason.

Option 2 is also the only one where the gateway's protected-resource metadata becomes
load-bearing, and see the OAuth note above before relying on it.

## Claude Code

Not verified here. Claude Code's `mcp add` takes a transport and headers; the same bearer
header applies. Check `claude mcp add --help` on your installed version rather than trusting a
snippet in this file.

## If it will not connect

| Symptom | Cause seen here |
| --- | --- |
| `exit 3`, `auth_required` | No `Authorization` header, or the key was revoked |
| `Protected resource ... does not match expected ...` | `localhost` vs `127.0.0.1`; make the client URL match `WARDEN_RESOURCE_URL` |
| `Dynamic Client Registration rejected (HTTP 404)` | The client fell back to OAuth; give it a static header instead |
| A tool you expect is missing from `tools/list` | Policy, or quarantine. `uv run warden tools list` shows both |
| `WARDEN_DENIED:policy` | Working as intended. `uv run warden audit tail --request-id <id>` says which rule |
| `WARDEN_PENDING:approval` | A risky tool. Approve it at `http://localhost:8080/approvals` |

The gateway logs every request as one JSON line, and every decision is a row in the audit log:

```bash
uv run warden audit tail --limit 20
```
