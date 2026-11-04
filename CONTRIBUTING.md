# Contributing

Thank you for helping improve AI Relay + ARPL. Contributions must preserve the
security boundaries described in [SECURITY.md](SECURITY.md).

## Before opening a change

- Read the README, relevant architecture docs, and current tests.
- Keep changes scoped; do not reset, stash, or overwrite unrelated work.
- Never include credentials, private keys, enrollment payloads, runtime state,
  production endpoints, machine identifiers, or release logs.
- Add tests for behavior changes and keep installer changes staging-first.
- Use explicit operator consent for activation and never turn a file path into
  a secret value in logs or command lines.

## Local checks

~~~sh
gofmt -w path/to/changed.go
GOCACHE=/tmp/ai-relay-go-build go test ./...
GOCACHE=/tmp/ai-relay-go-build go vet ./...
sh -n scripts/*.sh packaging/all-in-one/*.sh packaging/one-click/*.sh
~~~

Use a disposable HOME/XDG prefix for installer tests. Do not use
`--activate` against a live user session.

## Pull requests

Describe the user-visible behavior, security impact, tests run, and any native
OS gate that remains. Keep commits small and reviewable. A maintainer must
review changes to enrollment, credentials, cryptography, release packaging,
or service activation.

## Reporting

Use the issue templates for ordinary bugs and feature requests. For suspected
security issues, follow [SECURITY.md](SECURITY.md) and do not disclose a
working exploit in a public issue.

