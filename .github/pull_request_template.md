## Summary

## Security and release impact

- [ ] No credentials, private keys, enrollment payloads, runtime state, or production endpoints were added.
- [ ] Enrollment remains explicit and file-based.
- [ ] Native activation remains explicit and platform-owned.
- [ ] Documentation/status notes identify any native OS gates.

## Validation

- [ ] `gofmt`
- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] relevant shell syntax and installer safety checks
- [ ] release/archive checks if packaging changed

## Notes for reviewers

