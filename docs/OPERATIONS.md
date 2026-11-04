# Operations

## Local deployment

The gateway intentionally binds only to `127.0.0.1` (or another explicit loopback IP). Non-loopback plaintext HTTP is rejected; no public port is supported. Store MCP/admin tokens, enrollment tokens, and agent credentials in protected regular files: mode0600 on Unix, or an inheritance-disabled ACL limited to the current user, SYSTEM, and Administrators on Windows. The gateway creates `state.key` mode 0600 in its state directory on first start, unless `AI_RELAY_STATE_KEY_FILE` or `AI_RELAY_STATE_KEY` is supplied. State is AES-GCM encrypted and must be backed up together with its key.

Enrollment: create a 0600 one-use token file, then run `ai-relay-agent -gateway http://127.0.0.1:8743 -credential-file ~/.config/ai-relay/agent.cred -enroll-token-file ~/.config/ai-relay/enroll.token`. The agent writes JSON credentials mode 0600 and does not print the secret. Revoke with the device DELETE endpoint or MCP tool. Rotate by revoke/re-enroll.

## Services and remaining setup

For a non-root user, install binaries in `~/.local/bin`, create `~/.config/ai-relay/gateway.env` containing `AI_RELAY_MCP_TOKEN_FILE=...`, `AI_RELAY_MCP_ADMIN_TOKEN_FILE=...`, and optionally `AI_RELAY_STATE_KEY_FILE=...`, set all referenced files to 0600, copy both units from `deploy/systemd/user/` to `~/.config/systemd/user/`, then run `systemctl --user daemon-reload` and enable the units. Set `AI_RELAY_CODEX_BIN` to a current official Codex CLI executable controlled by the operator. `AI_RELAY_CODEX_SANDBOX` defaults to read-only; an explicit workspace-write setting supports development jobs only within the configured service filesystem policy. The root-managed units require an operator to create `ai-relay`/`ai-relay-agent`, protected credential files, and ownership/modes; the installer does not guess those secrets.

Recovery: stop the agent/gateway service; remove or rotate its credential; create the documented kill-switch file (`~/.config/ai-relay/disabled` for user services or `/etc/ai-relay/disabled` for the root unit); inspect `audit.jsonl`; restore state and `state.key` only from an operator-controlled backup. Do not delete audit evidence.

ChatGPT/custom MCP: expose only an authenticated TLS 1.3 reverse proxy or private tunnel, set its token through a secret file/secret manager, configure the MCP URL `/mcp`, and complete account/app authorization yourself. External account authorization and authenticated TLS termination remain deployment gates. Native desktop/input/USB helpers are not currently implemented.

## Windows user persistence

`deploy/install-windows.ps1 -Gateway URL -CredentialFile ENROLLED_FILE -AgentPath BINARY` installs a limited user-logon scheduled task. It does not register an SCM service or provide elevation. The installer verifies task restart, protects the executable/credential directory, and supports `-Uninstall` while preserving credentials. Gateway enrollment and real native task/MCP tests must pass before claiming Windows deployment.

## Resource and restart behavior

Idle agent polling is throttled; replay nonces expire and are capped without removing live replay protection. Queued jobs are restored after gateway restart; running jobs stay active awaiting their existing agent result. Executed commands are never blindly rerun. Agent results have a durable local outbox. Process output retains the last1MiB per stream and reports truncation explicitly. Incoming request/result bodies are bounded. Historical gateway job/audit records are preserved.

## Autonomous completion supervisor

`scripts/development-worker.py` is a Unix user supervisor for scoped project completion. Configure it with a repo, current official Codex CLI and private state directory. It serializes workers, writes status/logs, runs with workspace-write permissions, and retries with bounded backoff. Create `disabled` in its state directory to stop future runs. On Ubuntu24.04, load the packaged scoped bwrap AppArmor profile according to [official setup](https://learn.chatgpt.com/docs/sandboxing) so commands work without disabling global user-namespace restrictions. Verify actual inside/outside write boundaries and meaningful shell execution, not just a model reply.

The worker's state and optional public status files are committed with a temporary-file-plus-fsync-and-rename sequence. A second worker using the same state directory exits with code 75 without starting a child. Run `python3 scripts/test_control_plane.py` after changing these scripts; the test uses a no-op local child and does not invoke the official CLI or any service.

The isolated Mac watchdog uses the same loopback-safe scope: it may restart only the named 2.0 development worker when the remote branch is `develop/2.0`, free storage is at least 2 GiB, and no Codex writer is present. Otherwise it records `restart_suppressed_by_safety_gate`. Its local state and append-only log are written under the operator-selected private directory. Run `python3 scripts/test_watchdog.py` for bounded mocked-SSH coverage; this does not contact a host or restart a service. Native launchd/systemd restart evidence must still be collected by the trusted supervisor on the owning hosts.
