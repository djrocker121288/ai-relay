# Security policy

AI Relay + ARPL is intended for operator-owned or explicitly authorized
systems. Treat every relay endpoint, credential, private key, enrollment
token, payload, and runtime state file as sensitive.

## Reporting a vulnerability

Do not open a public issue for an undisclosed vulnerability. Contact the
repository owner through a private security channel configured on the GitHub
repository. Include a concise impact summary, affected version/commit,
reproduction steps that use disposable data, and a proposed mitigation when
available. Do not attach real credentials, private keys, production logs, or
machine identifiers.

If no private channel is configured yet, open a minimal public issue titled
"Private security contact needed" with no vulnerability details.

## Release and installer guarantees

- Enrollment requires an explicit protected credential or token file.
- Token contents are never accepted as CLI values or copied into release
  artifacts.
- The all-in-one installer stages ARPL persistence before any explicit native
  activation.
- UAC, TCC, Android permissions, code signing, and notarization are never
  bypassed or implied.
- Release archives are checked for obvious state, cache, credential, and
  private-key paths and include SHA-256 checksums.

## Operational guidance

Use trusted TLS for remote gateways, keep gateway listeners loopback-oriented
unless a deliberate authenticated boundary is configured, rotate credentials
after suspected exposure, and revoke affected devices. Inspect file modes and
Windows ACLs before allowing an agent to persist.

The project does not promise a complete OS sandbox. Run services with the
least privilege supported by the host and review generated service files
before activating them.

