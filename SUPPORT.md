# Support

Start with the README, [docs/INSTALL.md](docs/INSTALL.md), and the local
`status`/`doctor` output. Confirm the exact release version, host OS,
architecture, role, and whether activation was explicitly requested.

When opening a support issue, include:

- sanitized command and installer entry point (never token contents);
- exact error and exit code;
- relevant `doctor` output with endpoints, identities, and paths redacted;
- Go/PowerShell/Termux versions when applicable;
- whether the problem reproduces in a disposable directory.

Do not upload credentials, enrollment tokens, private keys, runtime state,
production logs, or screenshots containing secrets. Security issues belong in
[SECURITY.md](SECURITY.md), not a public support request.

