# Gemini CLI connection

AI Relay supports an optional Gemini CLI controller credential. The gateway remains loopback-only; use a trusted TLS 1.3 reverse proxy/private tunnel only when a remote client is required. Do not expose the gateway listener directly.

## Issue and revoke a credential

An administrator issues credentials separately for each controller. The token is returned once and is never written into gateway state (only a hash is persisted):

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $AI_RELAY_MCP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"gemini","scopes":["job.read","job.submit","job.control"]}' \
  http://127.0.0.1:8743/v1/controllers
```

Store the returned `token` in a local 0600 file or secret manager. Revoke it with the returned `id`:

```sh
curl -fsS -X DELETE -H "Authorization: Bearer $AI_RELAY_MCP_ADMIN_TOKEN" \
  http://127.0.0.1:8743/v1/controllers/CONTROLLER_ID
```

The controller identity is derived from the bearer credential. A request body field or header claiming to be another controller is ignored. Jobs are durably owned by the issuing controller; status, logs, stdin, and cancellation are denied across controllers.

## Official Gemini CLI HTTP configuration

Gemini CLI reads `mcpServers` from `settings.json`. The repository template uses the documented streamable HTTP `httpUrl` and `headers` fields. Replace the placeholders locally; never commit the token or modify a user’s Gemini account.

Copy [gemini-settings.example.json](gemini-settings.example.json) into the appropriate user/project configuration only after reviewing it, and substitute the token through your local secret-management process. The example deliberately uses a placeholder. The server alias contains no underscore because Gemini CLI uses the alias when forming tool names.

This repository verifies gateway-side MCP, authentication, ownership, revocation, audit, and loopback behavior. Gemini CLI account authorization, installation, and end-to-end tool discovery remain operator-side pending integration.

Official references: [Gemini CLI configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md) and [Gemini CLI MCP server guide](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md).

## Codex job tools

Codex submit/status/log/cancel tools are enabled only for the issuing controller. The gateway runs the configured Codex executable with the operator-configured sandbox (read-only by default) and no-approval flags, persists bounded job metadata/logs, enforces controller ownership, and records audit events. Verify the local Codex executable and service-account policy before enabling it in production.

## Observed account gate — October 13, 2026

On the deployment host, Gemini CLI is absent from PATH and neither the user Gemini configuration nor authentication directory exists. No existing authorized Gemini account connection was found. The example configuration parses, but this is not a Gemini execution test. The signed-in Codex backend is a different connection and does not authorize a Gemini or ChatGPT controller.

After account authorization is available, issue a distinct Gemini controller credential with the three documented job scopes, store it privately, configure `httpUrl` and the Authorization header, then verify `/mcp` tool discovery, a completed command job, controller ownership denial, and revocation. For a remote account client, first verify public DNS/TLS and proxy authorization. A ChatGPT connection must independently obtain account consent and use its own controller identity; do not reuse the Gemini credential. Never mark either integration complete based only on gateway HTTP tests.

Current official MCP reference: https://geminicli.com/docs/tools/mcp-server/
