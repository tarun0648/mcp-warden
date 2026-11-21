# How to run mcp-warden

Run the commands in order, in one terminal window.

## Before you start

If a gateway is already running on port 8080 (for example one started earlier for testing), stop it so it doesn't clash with the one you're about to start:

```bash
pkill -f "warden serve"
```

---

## Getting an API key

The console and the MCP endpoint both need an API key. None comes built in: you create your own, and any key you create works for signing in.

**If a gateway is already running from the project folder** (not Docker), create a key for it with:

```bash
cd "/Users/taruns/Documents/CLAUDE PROJECT 1/mcp-warden" && .venv/bin/warden keys create --user you --roles admin
```

It prints something like:

```
key created. This is the only time it is shown:

  wdn_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Copy that whole `wdn_...` string, open http://localhost:8080/console, paste it into the **API key** box and click **Sign in**.

- Use `--roles admin` to see everything: tools, API keys, policy and approvals.
- To see what a normal user sees, make a second key with `--roles reader` or `--roles editor` and sign in with that instead.
- Once you're in as admin, you can create more keys from the **API keys** page, without the terminal.
- **The key is shown only once.** If you lose it, create a new one; the old one can't be recovered.
- **Docker and the direct run use separate databases**, so a key from one doesn't work in the other. For the Docker version (`make up-all`), create the key with:

```bash
docker compose exec gateway warden keys create --user you --roles admin
```

---

## Option 1: everything in Docker (recommended)

You need Docker Desktop and Node.js.

**1. Start Docker Desktop**

```bash
open -a Docker
```

**2. Go to the project**

```bash
cd "/Users/taruns/Documents/CLAUDE PROJECT 1/mcp-warden"
```

**3. Create your settings file** (skipped if you already have one)

```bash
cp -n .env.example .env
```

**4. Start the whole stack**

This starts the gateway, its tool servers, Postgres, Redis, Jaeger, Prometheus and Grafana. The first build takes a few minutes.

```bash
POSTGRES_HOST_PORT=55432 REDIS_HOST_PORT=56379 make up-all
```

> On this Mac, Homebrew's Postgres and Redis already use ports 5432 and 6379, so the two settings at the front move Docker's copies to other ports. On a Mac without them, plain `make up-all` works.

**5. Create an admin key**

Copy the whole `wdn_...` value it prints. It is shown only once.

```bash
docker compose exec gateway warden keys create --user you --roles admin
```

**6. Open the console and sign in with that key**

```bash
open http://localhost:8080/console
```

**7. Stop everything when you're done** (your data is kept)

```bash
make down
```

### Other pages in the Docker stack

| What | Where |
| --- | --- |
| Console | http://localhost:8080/console |
| Approval page | http://localhost:8080/approvals |
| Grafana dashboards | http://localhost:3000 |
| Jaeger traces | http://localhost:16686 |
| Prometheus | http://localhost:9090 |

---

## Option 2: run directly on your Mac (no Docker)

This uses a Postgres and Redis already running on your Mac (Homebrew). You also need `uv` (`brew install uv`).

**1. Go to the project**

```bash
cd "/Users/taruns/Documents/CLAUDE PROJECT 1/mcp-warden"
```

**2. Install the dependencies**

```bash
make setup
```

**3. Set up the database and the signing key**

```bash
uv run warden db upgrade && uv run warden keys init-jwt
```

**4. Create an admin key** (copy the `wdn_...` value it prints)

```bash
uv run warden keys create --user you --roles admin
```

**5. Start the gateway** (leave it running; press `Ctrl+C` to stop)

```bash
make run
```

**6. Open the console** in your browser at http://localhost:8080/console and sign in with the key.

---

## Things to try in the console

| Try this | What you'll see |
| --- | --- |
| **Playground:** run `files__read_file` with `{"path": "../../etc/passwd"}` | Refused with `WARDEN_DENIED:policy`; the call never reaches the tool |
| **Playground:** run `notes_db__list_notes` with `{}` | Allowed, with the real result and every check it passed |
| **Playground:** run `files__delete_file` | Waits for approval. A *second* admin key has to approve it on **Approvals**: nobody can approve their own call |
| **API keys:** create a key with the `reader` role, sign out, sign in with it | What a normal user sees: only their own tools and activity |
| **Activity:** click **Verify the chain** | Checks that nobody has tampered with the audit log |
| **Tools:** open a tool and click **Quarantine** | The tool disappears for every role until you approve it again |

### Which key to use

- **Admin key** (`--roles admin`): sees and manages everything.
- **Reader** or **editor** key (`--roles reader` / `--roles editor`): sees only their own tools, calls and requests.
- Once you're signed in as admin, you can create more keys from the **API keys** page instead of the terminal.
- A key is shown only once. If you lose it, create a new one.

---

## Using it from an MCP client instead of the console

Put your key in a variable (paste your `wdn_...` value):

```bash
KEY=wdn_paste_your_key_here
```

List the tools your role can see:

```bash
npx -y @modelcontextprotocol/inspector --cli http://localhost:8080/mcp --transport http --method tools/list --header "Authorization: Bearer $KEY"
```

Make a call the policy refuses:

```bash
npx -y @modelcontextprotocol/inspector --cli http://localhost:8080/mcp --transport http --method tools/call --tool-name files__read_file --tool-arg 'path=../../etc/passwd' --header "Authorization: Bearer $KEY"
```

More clients (Cursor, Claude Desktop) are covered in [docs/clients.md](docs/clients.md).

---

## Other useful commands

| Command | What it does |
| --- | --- |
| `make test` | Runs the unit and integration tests (about 3 minutes) |
| `make lint` | Checks code style and types |
| `make security` | Scans the code and dependencies for known problems |
| `make demo SCENARIO=all` | Runs the five attack scenarios |
| `make redteam` | Runs every attack and benign case and writes `results/` |
| `make bench` | Measures how much time the gateway adds to each call |
| `make help` | Lists every command |

---

## If something goes wrong

| Problem | Fix |
| --- | --- |
| `failed to connect to the docker API` | Docker Desktop isn't running: `open -a Docker`, wait a few seconds, try again |
| `address already in use` on port 8080 | Another gateway is running: `pkill -f "warden serve"`, or `make down` for Docker |
| "That key was not accepted" in the console | Wrong or revoked key, or a key from the other option (Docker and the direct run use separate databases). Create a new one |
| A page says **Admins only** | You signed in with a non-admin key. Sign out and use an admin key |
| You signed out after a restart | Expected: console sessions are kept in memory. Sign in again |
