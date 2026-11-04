# AI Relay 2.0 interaction fallback boundary

`internal/v2/interaction` is the additive P7 policy core. It selects an
already-advertised adapter in this fixed order:

1. API
2. terminal
3. accessibility
4. visual GUI

The package does not invoke an API, spawn a terminal, contact an accessibility
framework, inspect a display, or open an account/security dialog. A future
adapter must advertise both capability and explicit operator-consent state;
availability without `granted` consent is never selectable. Unknown,
duplicate, oversized, or malformed advertisements fail closed.
Adapter authors may call the additive `Capability.Validate` method before
publishing an individual advertisement; it checks only the bounded method,
consent, and detail fields and never probes a platform or treats availability
as consent. `ValidateCapabilities` applies the same checks to a complete
publication, rejects duplicate methods, and enforces the four-adapter ceiling
before a registry exposes the set. `Select` and `Execute` repeat the complete
validation at their own boundaries.
`NewAdapterRegistry` is the bounded ownership handoff for that publication: it
rejects nil, panicking, duplicate, and malformed adapters, snapshots immutable
membership, exposes only a copied capability snapshot, and delegates execution
back to the same policy boundary. It does not expose a raw adapter lookup:
callers cannot bypass selection, consent revalidation, output bounds, or visual
evidence checks by invoking an adapter directly. The registry binds each
adapter to the method published at registration; a later method change is
ownership drift and fails closed as unavailable rather than becoming an
implicit fallback or changing the adapter's registry slot. Adapter capability
state may still change inside the implementation, so selection and execution
re-read and revalidate it before invocation, including a method-binding check
across the execution preflight.
If a bound adapter reports a different method during that handoff, the shared
selector treats it as an ownership failure and returns unavailable before
considering any lower-priority registry member; ownership drift is never an
implicit fallback signal.
The registration snapshot is compacted to the members that are present while
retaining their relative API/terminal/accessibility/visual order; a registry
with no API member is valid and starts at its first registered fallback method.
`Capabilities` remains the immutable registration snapshot for audit and
ownership inspection, but it rechecks each member's method binding before
publishing so a stale snapshot cannot survive ownership drift. Other live
fields remain the registration snapshot on this method. `CurrentCapabilities`
is the live, validated publication for a future controller or discovery
boundary: it re-reads the exact registry members in fallback order and fails
closed on method ownership drift, malformed capability state, or adapter
inspection failure. Neither method invokes `Execute`, grants consent, or
discovers an account/platform on the registry's behalf.
The registry also revalidates its own non-nil map, compact relative-order
snapshot, member count, and method-to-adapter membership before exposing either
publication or starting selection/execution. This keeps zero-value and
package-local malformed registries from becoming an authority boundary; live
capability changes remain allowed only through the separate handoff rechecks.
`AdapterRegistry.Select` provides the corresponding side-effect-free planning
operation. It re-reads and validates the current capability publication for
the registry's exact members before applying the same fallback order, so a
revoked consent or changed session is reflected in an inspectable plan without
invoking an adapter. A planning result is descriptive only; execution still
performs its own cancellation and capability checks immediately before the
adapter call. The registry adds one final method, availability, consent, and
bounded-session-detail handoff check inside its bound adapter immediately
before delegation, including a check that the selected plan is still bound to
that registry method; late ownership, plan, consent, or session-detail drift
returns unavailable and cannot reach the native implementation. This final
handoff is distinct from shared pre-invocation revalidation and is not a
fallback signal.

Visual selection is deliberately narrow. It requires a bounded display
rectangle within a bounded screen size, rejects control and Unicode format
characters in bounded metadata and oversized labels, and returns a plan that
requires bounded, distinct
before/after evidence references. The two references must not be the same
artifact, so presence alone cannot masquerade as before/after evidence.
Any supplied visual target is validated before selection, even when API,
terminal, or accessibility wins the fallback order; non-visual plans still
omit the target from the plan while their adapter request receives only the
validated bounded copy.
`ValidateVisualEvidence` treats every visual plan as
evidence-bearing even if a caller supplies a malformed plan with its derived
flag cleared; the flag is descriptive output, not an authorization to bypass
the safety boundary. It also revalidates the plan's bounded operation,
explicitly granted consent, capability detail, and visual target before
accepting evidence, so caller-constructed plans cannot turn two references
into an authorization. The helper validates references but does not read,
upload, or log screenshots. Any action that would interact with
an OS or account security dialog is rejected with `ErrSecurityDialog`; no
fallback may click through or dismiss such a prompt.
An inconsistent caller-constructed non-visual plan that sets the derived
visual-evidence flag is rejected as malformed rather than silently treated as
an evidence-free non-visual result.

The `interaction.Execute` boundary is the only shared execution helper. It
validates the caller context before inspecting any adapter, validates the
request and security-dialog policy before inspecting any adapter, and
derives capabilities from the supplied adapter objects, re-runs the fixed
selection and consent checks, invokes exactly the selected adapter, and passes
it copies of the request target and any pointer-bearing visual plan target. An
adapter cannot mutate the policy decision returned to the caller through
either pointer. Before invocation it re-reads the selected
adapter's capability and fails closed if any bounded capability field changed
since selection, or if availability, method, or explicit consent no longer
matches the selected plan; this prevents a session/target change or revoked
adapter from starting an action under a stale selection. A nil or typed-nil context is rejected before adapter
inspection, a context that panics during cancellation inspection fails closed
before adapter inspection, and unsupported caller-owned context errors are
reduced to generic `ErrInvalid` while canonical cancellation and deadline
signals remain available. The registry performs the same entry preflight
before its ownership refresh, so a canceled or malformed context cannot
trigger registry-owned capability inspection. The context is rechecked both
after selection and immediately after capability revalidation so cancellation
during capability inspection or selection cannot start an action;
malformed operations, invalid targets, and security-dialog requests are
rejected before direct or registry-owned capability inspection;
literal-nil and typed-nil adapters are rejected before capability inspection;
adapter panics and adapter-specific errors are reduced to the generic
`ErrAdapter` boundary; returned output must be valid UTF-8 before it can cross
the boundary and is capped at 64 KiB. Terminal control characters, bidi
overrides, and other Unicode format controls are rejected (tab, line feed, and
carriage return remain available for ordinary multiline output). Invalid or
terminal-active output is rejected as a generic adapter failure rather than
being normalized by a later JSON or logging layer. Optional evidence references
are bounded and validated for every result, including non-visual results;
visual plans additionally require both non-empty references and distinct
before/after values.

The selected `Plan` also retains the exact bounded `Capability.Detail` snapshot
that was validated during selection. This is descriptive audit metadata, not a
new authority or consent grant; `Execute` still revalidates the complete
capability immediately before invocation and fails closed on any change.
If the context is canceled while an adapter is running, a successful adapter
result is discarded and the caller receives the context cancellation instead;
the adapter remains responsible for stopping its own side effects when the
platform supports cancellation. Visual results must include both bounded
before/after evidence references after the action.
This helper still does not implement or authorize a native adapter, and an
adapter remains responsible for honoring cancellation during its own
operation.

Operation names, capability details, visual labels, evidence references, and
adapter output are valid UTF-8 but fail closed on Unicode control and format
characters, including bidi overrides and zero-width controls, as well as
Unicode line and paragraph separators (U+2028/U+2029). Ordinary non-ASCII text
remains allowed. This keeps policy metadata and bounded results from rendering
or recording as a different visual/logical structure than the value that was
validated.

This checkpoint uses only the Go standard library. No mature external
component was reused: the policy is small, deterministic, offline, and has no
runtime or transitive dependency footprint. That keeps maintenance and
security review local, makes rollback equivalent to removing this isolated
package, and leaves platform adapter choice replaceable. Native accessibility
and visual implementations remain separate capability/consent-gated work.

The package is not wired to the 1.x gateway, agent, ChatGPT, Codex, Gemini,
desktop sessions, or account discovery. It does not claim P7 completion or
native capability evidence. A later integration must preserve API/terminal
precedence, authenticate ownership, obtain consent through the platform's
normal controls, retain before/after evidence, and keep security dialogs
outside the action target.
