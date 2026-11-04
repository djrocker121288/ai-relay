# Grok connection

AI Relay exposes an MCP JSON-RPC endpoint that Grok can use as a connector.
The gateway remains loopback-only by default. For remote Grok clients (grok.com
or Grok Bot), expose it only through a trusted TLS 1.3 reverse proxy or private
tunnel. Do not bind the gateway to a non-loopback address.

## Issue a controller credential

An administrator issues a controller credential for Grok. The token is returned
once and is never stored in plaintext by the gateway (only a hash is persisted):

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $AI_RELAY_MCP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"grok","scopes":["job.read","job.submit","job.control"]}' \
  http://127.0.0.1:8743/v1/controllers
```

Store the returned `token` in a local 0600 file or secret manager. Revoke it
with the returned `id`:

```sh
curl -fsS -X DELETE -H "Authorization: Bearer $AI_RELAY_MCP_ADMIN_TOKEN" \
  http://127.0.0.1:8743/v1/controllers/CONTROLLER_ID
```

The controller identity is derived from the bearer credential. Jobs are owned
by the issuing controller; status, logs, stdin, and cancellation are denied
across controllers.

## Grok Build / CLI (local or tunneled)

Grok Build and the Grok CLI support remote HTTP MCP servers with static
Authorization headers.

### One-command add

```sh
# Local loopback (CLI running on the same host as the gateway)
grok mcp add --transport http ai-relay http://127.0.0.1:8743/mcp \
  --header "Authorization: Bearer $AI_RELAY_GROK_TOKEN"

# Or via a public HTTPS tunnel / reverse proxy
grok mcp add --transport http ai-relay https://relay.example.com/mcp \
  --header "Authorization: Bearer $AI_RELAY_GROK_TOKEN"
```

### config.toml

Add to `~/.grok/config.toml` (or `.grok/config.toml` for project scope):

```toml
[mcp_servers.ai-relay]
url = "http://127.0.0.1:8743/mcp"   # or your HTTPS tunnel URL
headers = { Authorization = "Bearer ${AI_RELAY_GROK_TOKEN}" }
enabled = true
```

Grok expands `${VAR}` from the environment at load time, so the token can stay
out of the config file. Use `--scope project` with `grok mcp add` to write
`.grok/config.toml` in the current repository instead of the user config.

Verify with:

```sh
grok mcp list
grok mcp doctor ai-relay
```

## grok.com / Grok Bot (remote)

On grok.com, open **Connectors** → **New Connector** → **Custom** and paste a
public HTTPS MCP URL. Grok rejects `localhost`, `127.0.0.1`, and private ranges.

Use a reverse proxy or tunnel that terminates TLS and forwards to the loopback
gateway `/mcp` path, and supply the bearer token when Grok prompts for
authentication.

For Grok Bot, ask it to add a custom MCP server and provide the public URL.
Authorization is completed via a browser card.

## Available tools

Once connected, Grok can call the MCP tools exposed by the gateway, including:

- `health` — gateway and device health
- `devices.list` — list enrolled devices
- `devices.enroll_token` / `devices.revoke` — admin device management
- `agent.exec` / `agent.job` / `agent.cancel` / `agent.stdin` — remote agent jobs
- `manager.submit` / `manager.status` / `manager.result` / `manager.jobs` / `manager.cancel`
- `codex.job.submit` / `codex.job.status` / `codex.job.log` / `codex.job.cancel`
- `confidence.evaluate` — auditable decision helper

Scopes required for each tool are enforced by the gateway. See
[docs/GEMINI-CLI.md](GEMINI-CLI.md) for the parallel controller credential
pattern and [docs/OPERATIONS.md](OPERATIONS.md) for deployment notes.

## Security notes

- Prefer the loopback gateway for local CLI use.
- For remote access, use only an authenticated TLS reverse proxy or private
  tunnel; never expose the plaintext loopback listener.
- Controller tokens are single-use issuance; rotate by revoke + re-issue.
- Do not commit tokens or place them in shared configuration.
