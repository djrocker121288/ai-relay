# Threat model

Protect against unauthenticated remote execution, credential replay, revoked-device use, accidental LAN exposure, audit tampering, and privilege confusion. Trust anchors are the operator-controlled MCP token/admin role, enrollment ceremony, device secret/private key, OS service account, and local emergency disable. HMAC binds request contents; timestamps/nonces limit replay; atomic 0600 state/audit permissions limit local disclosure. The default listener is loopback-only; any LAN/private-tunnel deployment must add TLS 1.3 and authenticated proxy policy.

Out of scope: a fully compromised endpoint kernel, malicious operator, stolen unlocked root session, or a compromised reverse proxy. Mitigations still include least-privilege services, explicit privileged flags, noninteractive elevation, resource limits, bounded output, audit records, and kill switches. Review all network binding and firewall rules before LAN use.
