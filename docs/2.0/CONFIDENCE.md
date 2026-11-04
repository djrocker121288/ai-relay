# P4 confidence and escalation

`internal/v2/confidence` is a side-effect-free policy core. Callers provide
bounded evidence; the package returns a decision record and does not execute a
task, contact a controller, or grant a permission.

The score is the stable, name-ordered weighted sum of finite evidence scores in
the closed interval `[0,1]`. Evidence names are unique, each input names a
bounded calibration method, and weights must sum to one. Policy
`ai-relay-confidence/v1` requires all three dimensions:

- deterministic validation;
- runtime/model suitability;
- task risk, expressed as confidence that the bounded action is safe (higher is
  safer).

The default thresholds are:

- `>= 0.80`: `auto`
- `0.50–0.79`: `escalate`
- `< 0.50`: `reject`

Evidence should include deterministic validation results, runtime/model
evidence, and a task-risk assessment. The caller must document how each score
was calibrated; a successful model response alone is not a validation pass.

Escalation is deny-by-default: the target must be listed in
`AllowedTargets`, and every requested scope must already exist in
`AuthorizedScopes`. This prevents low confidence from becoming a privilege
expansion. The resulting record contains the inputs, outcome, UTC timestamp,
authenticated controller/owner ID, complete versioned policy, and a SHA-256
digest. `Verify` both checks record
integrity and re-evaluates the stored evidence under the stored policy, so a
caller cannot change an outcome and merely recompute the checksum. Callers must
still pin the accepted policy ID and protect the record in an authenticated or
append-only store: an unkeyed SHA-256 digest is integrity evidence, not an
identity signature. P5 owns authenticated storage/signing material.

The gateway now exposes the additive MCP tool `confidence.evaluate`. It uses
the fixed `ai-relay-confidence/v1` policy, allows only the pre-authorized
`human` and `controller` targets, always permits the inert `read-repo` action
description, and permits `job.read` or `job.submit` only when the authenticated
caller already owns the matching gateway scope. The dedicated
`confidence.evaluate` controller scope is opt-in: existing legacy and default
controller credentials do not gain it during upgrade. Unknown request fields
are rejected. The tool binds the authenticated controller ID into the digested
decision, returns the verified decision, and appends its digest, controller
owner, target, and requested scopes to the audit log. It does not
execute work, contact a human/controller, grant a scope, or alter terminal and
scheduler boundaries. Controllers without the dedicated scope fail closed.

The MCP adapter preserves controller ownership, versioned initialization,
bounded outputs, and the existing authenticated transport. Actual human or
remote-controller delivery remains a separate consent/external gate; an
escalation decision is evidence of required escalation, not proof that contact
occurred.
