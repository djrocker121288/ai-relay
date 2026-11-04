# AI Relay distribution service

The distribution service is designed to remain on loopback
(`127.0.0.1:18787` in the packaged unit). Put an operator-approved,
authenticated TLS reverse proxy or private tunnel in front of it. Do not bind
it directly to a public interface and do not publish it without authentication.

The service accepts `AI_RELAY_TUNNEL_PROVIDER`,
`AI_RELAY_TUNNEL_HOSTNAME`, `AI_RELAY_TUNNEL_TARGET`, and
`AI_RELAY_TUNNEL_CONFIG` (or equivalent flags) so each deployment can supply
its own provider settings. The public unit intentionally leaves the tunnel
provider and hostname blank. AI Relay does not require provider credentials in
this repository.

## Tunnel handoff

Configure the authorized tunnel/reverse-proxy provider to route its
authenticated hostname to `http://127.0.0.1:18787`. Permit only the
distribution endpoints actually required by the deployment, such as signed
artifact/manifest paths and any explicitly enabled telemetry/report endpoints.
Reject unrelated paths.

Before enabling public DNS, verify:

- the service still listens only on loopback;
- TLS is valid and terminates at an operator-controlled boundary;
- the external boundary requires the intended identity/access policy;
- unauthenticated requests are denied;
- signed update manifests use the deployment owner's pinned key;
- telemetry remains opt-in and has an explicitly configured endpoint;
- diagnostic report submission requires explicit user approval and an
  explicitly configured endpoint.

The packaged unit is a template only. It does not change DNS, tunnel accounts,
certificates, firewall rules, provider settings, or public hostnames.

Distribution currently relies on the operator to provide the authenticated
external boundary. A configured tunnel hostname is metadata, not proof that
DNS, TLS, or authorization is correct.
