# P8 workflow-definition boundary

`internal/v2/workflow` is the first provider-neutral workflow foundation for
2.0. It is deliberately side-effect-free: definitions are validated in
memory, and `Plan` returns a deterministic forward DAG plus reverse-order
compensation declarations. It does not execute commands, contact tunnel
providers, persist state, store artifacts, or grant an approval.

Definitions support:

- event or bounded interval triggers, with exactly one trigger mode;
- step dependencies with duplicate, missing-reference, self-reference, and
  cycle rejection;
- bounded retry attempts and delays;
- explicit approval scopes, which cannot be supplied without `Required` being
  true;
- optional compensation actions and bounded artifact retention/size policy.

`ApprovalPolicy.SatisfiedBy` provides the corresponding bounded policy check
for a future runner. It requires every declared scope for a required approval,
rejects duplicate, malformed, or oversized grant scope lists, and accepts
unrelated additional scopes so callers do not need to rewrite an authenticated
grant before evaluation. It is intentionally not an approval authority: it
does not verify the grant's issuer, identity, expiry, signature, or storage,
and a runner must perform those checks at its authenticated boundary before
calling the helper.

All workflow IDs, names, event names, actions, compensation actions, and
approval scopes must be valid UTF-8 without leading/trailing padding, Unicode
control characters (including the C1 range), Unicode format characters, or
Unicode line/paragraph separators (U+2028/U+2029). This rejects
invisible/ordering-sensitive characters such as zero-width characters and
bidirectional overrides, plus characters that can create a new visual/logical
record, keeping logs and downstream policy parsing unambiguous; invalid text
is rejected before trigger evaluation or planning.

The definition boundary also exposes deterministic policy evaluation without
starting work: `MatchesEvent` validates and compares an event trigger, while
`ScheduleDue` evaluates an interval against caller-supplied timestamps. A
first interval run is due immediately; a backwards clock is rejected. Retry
policies expose a 1-based `Delay` calculation with saturating exponential
backoff and a `MaxWait` cap. `MaxAttempts` includes the initial attempt, and
invalid retry numbers fail closed. `RetryPolicy.CanRetry` exposes the matching
1-based eligibility check, so a future runner does not need to infer retry
authority from a delay error. Attempt zero and malformed policies fail closed;
reaching `MaxAttempts` returns a valid non-retry decision. These helpers do
not schedule or execute work.

`ArtifactPolicy.AllowsSize` rejects negative sizes and reports whether a size
fits the configured limit; an omitted limit is treated as no configured size
limit. `ArtifactPolicy.RetentionDue` reports the exact retention boundary and
rejects missing or backwards timestamps when retention is configured. These
helpers do not read, write, delete, or persist artifacts; a future runner must
apply the result at its authenticated, durable storage boundary.

The planner uses stable step IDs to break ties in the topological ordering.
Compensations are returned in reverse topological order. `Plan.CompensationsFor`
is the bounded policy helper for a future runner: it accepts a unique set of
completed step IDs in any caller order, rejects IDs outside the plan, and
returns copies only for completed steps that declare compensation. It derives
the reverse order from the validated plan rather than trusting the plan's
optional compensation slice. It does not execute, persist, or authorize the
returned actions. This package contains no executor, scheduler, approval
service, tunnel client, or credential handling; those remain separate reviewed
boundaries. A future durable runner must bind each execution to an
authenticated owner, persist an idempotency key and attempt record, and apply
its own atomic checkpoint/retry policy.

The implementation uses only the Go standard library. That keeps the idle
footprint and dependency/security surface negligible, works offline, and makes
the planner replaceable by deleting this isolated package. No mature external
component was imported. The rollback path is removing the v2 package and this
document; existing 1.x distribution, gateway, agent, and service routes are
unchanged.

The interval trigger, retry, and retention bounds are policy validation rather
than proof that a scheduler or storage provider is healthy. Provider
configuration, authenticated distribution, audit/retention storage, and
workflow execution remain later P8 gates; these helpers must not be
represented as a scheduler health, provider health, or deployment result.
