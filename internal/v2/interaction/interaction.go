// Package interaction contains the transport-neutral policy boundary for the
// P7 interaction fallback stack. It selects an already-advertised adapter; it
// does not invoke APIs, terminals, accessibility frameworks, or GUI tools.
package interaction

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"unicode"
	"unicode/utf8"
)

const (
	maxOperationBytes   = 128
	maxCapabilityCount  = 4
	maxDetailBytes      = 256
	maxTargetLabelBytes = 128
	maxEvidenceRefBytes = 512
	maxScreenDimension  = 16384
	maxOutputBytes      = 64 << 10
)

var (
	ErrInvalid        = errors.New("invalid interaction request")
	ErrUnavailable    = errors.New("no consented interaction adapter is available")
	ErrSecurityDialog = errors.New("security-dialog interaction is not permitted")
	ErrVisualEvidence = errors.New("visual before/after evidence is required")
	ErrVisualTarget   = errors.New("visual target is invalid")
	ErrAdapter        = errors.New("interaction adapter failed")
	ErrOutputTooLarge = errors.New("interaction adapter output exceeds limit")
)

// Method is one step in the required fallback order.
type Method string

const (
	MethodAPI           Method = "api"
	MethodTerminal      Method = "terminal"
	MethodAccessibility Method = "accessibility"
	MethodVisual        Method = "visual"
)

var methodOrder = [...]Method{MethodAPI, MethodTerminal, MethodAccessibility, MethodVisual}

// ConsentState is the explicit operator-consent state advertised by an
// adapter. Unknown and required states are intentionally not equivalent to
// granted.
type ConsentState string

const (
	ConsentUnknown  ConsentState = "unknown"
	ConsentRequired ConsentState = "required"
	ConsentGranted  ConsentState = "granted"
	ConsentDenied   ConsentState = "denied"
)

// Capability is an adapter's bounded, non-secret advertisement. The adapter
// implementation remains outside this package and must not infer consent from
// availability alone.
type Capability struct {
	Method    Method
	Available bool
	Consent   ConsentState
	Detail    string

	// ownershipDrift is an internal handoff marker. It cannot be supplied by
	// an external adapter, but it lets the shared selector distinguish a
	// registry ownership change from an ordinary denied capability and fail
	// closed instead of falling through to another registry member.
	ownershipDrift bool
}

// Validate checks a capability before an adapter publishes or registers it.
// It performs only bounded, transport-neutral validation; it does not probe
// the advertised platform or infer consent from availability.
func (capability Capability) Validate() error {
	return capability.validate()
}

// ValidateCapabilities checks a complete capability publication before it is
// registered or exposed to a selector. It validates every bounded
// advertisement, rejects duplicate methods, and caps the publication size;
// it does not probe a platform or infer consent.
func ValidateCapabilities(capabilities []Capability) error {
	if len(capabilities) > maxCapabilityCount {
		return fmt.Errorf("%w: too many adapter capabilities", ErrInvalid)
	}
	seen := make(map[Method]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if err := capability.Validate(); err != nil {
			return err
		}
		if _, exists := seen[capability.Method]; exists {
			return fmt.Errorf("%w: duplicate adapter method", ErrInvalid)
		}
		seen[capability.Method] = struct{}{}
	}
	return nil
}

// VisualTarget identifies a bounded display rectangle. Coordinates are
// display-relative and are validated without contacting a display server.
type VisualTarget struct {
	Label        string
	X            int
	Y            int
	Width        int
	Height       int
	ScreenWidth  int
	ScreenHeight int
}

// Request is the non-secret description used for deterministic selection.
// SecurityDialog must be set when an action would interact with an OS or
// account security prompt; the policy rejects it rather than bypassing it.
type Request struct {
	Operation      string
	Mutating       bool
	SecurityDialog bool
	Target         *VisualTarget
}

// Plan is the selected adapter contract. A visual plan always requires the
// caller to capture and validate before/after evidence after execution.
type Plan struct {
	Method    Method
	Operation string
	Mutating  bool
	Consent   ConsentState
	// CapabilityDetail is the bounded detail advertised by the selected
	// adapter. Preserve the exact validated snapshot so audit and adapter
	// consumers do not have to re-read mutable capability state to explain the
	// selection that was made.
	CapabilityDetail       string
	RequiresVisualEvidence bool
	Target                 *VisualTarget
}

// VisualEvidence contains non-secret references to bounded before/after
// evidence. References may identify supervisor-retained evidence; this package
// does not read, upload, or log them.
type VisualEvidence struct {
	Before string
	After  string
}

// Result is the bounded, non-secret result returned by an adapter. Visual
// adapters must provide evidence references after the action completes;
// this package does not inspect or retain the referenced artifacts.
type Result struct {
	Output   string
	Evidence VisualEvidence
}

// Adapter is the narrow execution contract for a platform integration. The
// adapter owns API/terminal/accessibility/GUI details, while this package
// revalidates its advertised capability and consent before invocation.
type Adapter interface {
	Capability() Capability
	Execute(context.Context, Request, Plan) (Result, error)
}

// Select chooses the first available and explicitly consented method in the
// fixed API, terminal, accessibility, visual order. Input capability order is
// irrelevant, and duplicate or malformed advertisements fail closed.
func Select(request Request, capabilities []Capability) (Plan, error) {
	if err := validateSelectionRequest(request); err != nil {
		return Plan{}, err
	}
	if err := ValidateCapabilities(capabilities); err != nil {
		return Plan{}, err
	}
	available := make(map[Method]Capability, len(capabilities))
	for _, capability := range capabilities {
		available[capability.Method] = capability
	}

	var visualTargetErr error
	for _, method := range methodOrder {
		capability, ok := available[method]
		if !ok || !capability.Available || capability.Consent != ConsentGranted {
			continue
		}
		var target *VisualTarget
		if method == MethodVisual {
			if request.Target == nil {
				visualTargetErr = ErrVisualTarget
				continue
			}
			if err := request.Target.validate(); err != nil {
				visualTargetErr = err
				continue
			}
			copy := *request.Target
			target = &copy
		}
		return Plan{
			Method:                 method,
			Operation:              request.Operation,
			Mutating:               request.Mutating,
			Consent:                capability.Consent,
			CapabilityDetail:       capability.Detail,
			RequiresVisualEvidence: method == MethodVisual,
			Target:                 target,
		}, nil
	}
	if visualTargetErr != nil {
		return Plan{}, visualTargetErr
	}
	return Plan{}, ErrUnavailable
}

// ValidateVisualEvidence enforces the evidence requirement of a visual plan.
// It accepts references only; it deliberately does not inspect or expose
// screenshots, window contents, credentials, or security dialogs.
func ValidateVisualEvidence(plan Plan, evidence VisualEvidence) error {
	// Treat every visual method as evidence-bearing even if a malformed or
	// caller-constructed plan clears the derived flag. The flag is descriptive
	// output from Select, not an authorization to bypass the visual boundary.
	if plan.Method != MethodVisual {
		if plan.RequiresVisualEvidence {
			return fmt.Errorf("%w: non-visual plan cannot require visual evidence", ErrVisualEvidence)
		}
		return nil
	}
	// Evidence is only meaningful for a plan that could have been selected by
	// this package. A caller must not be able to turn an arbitrary visual plan
	// into an apparently authorized action by supplying two well-formed
	// references. Keep the public error classification at the evidence boundary
	// while validating the bounded operation, consent, capability detail, and
	// target that Select would have required.
	if err := validateVisualPlan(plan); err != nil {
		return fmt.Errorf("%w: visual plan: %v", ErrVisualEvidence, err)
	}
	if err := validateEvidenceReference(evidence.Before); err != nil {
		return fmt.Errorf("%w: before evidence: %v", ErrVisualEvidence, err)
	}
	if err := validateEvidenceReference(evidence.After); err != nil {
		return fmt.Errorf("%w: after evidence: %v", ErrVisualEvidence, err)
	}
	if evidence.Before == evidence.After {
		return fmt.Errorf("%w: before and after evidence must be distinct", ErrVisualEvidence)
	}
	return nil
}

func validateVisualPlan(plan Plan) error {
	if err := validateText(plan.Operation, maxOperationBytes, false); err != nil {
		return fmt.Errorf("operation: %v", err)
	}
	if plan.Consent != ConsentGranted {
		return errors.New("explicit consent is required")
	}
	if err := validateText(plan.CapabilityDetail, maxDetailBytes, true); err != nil {
		return fmt.Errorf("capability detail: %v", err)
	}
	if plan.Target == nil {
		return errors.New("visual target is required")
	}
	if err := plan.Target.validate(); err != nil {
		return err
	}
	return nil
}

// Execute selects and invokes exactly one already-advertised adapter. It is a
// transport-neutral boundary: no platform API, terminal, accessibility
// framework, display server, account, or security dialog is contacted here.
// A cancelled context prevents invocation, adapter panics are contained, and
// returned output is bounded before it can cross a caller's transport.
func Execute(ctx context.Context, request Request, adapters []Adapter) (plan Plan, result Result, err error) {
	if err := validateExecutionContext(ctx); err != nil {
		return Plan{}, Result{}, err
	}
	// Reject malformed or security-sensitive requests before inspecting any
	// adapter-owned capability code. Capability inspection is an adapter
	// boundary, so a request that cannot be selected must not reach it.
	if err := validateSelectionRequest(request); err != nil {
		return Plan{}, Result{}, err
	}
	if len(adapters) > maxCapabilityCount {
		return Plan{}, Result{}, fmt.Errorf("%w: too many adapters", ErrInvalid)
	}
	capabilities := make([]Capability, len(adapters))
	for i, adapter := range adapters {
		if nilAdapter(adapter) {
			return Plan{}, Result{}, fmt.Errorf("%w: nil adapter", ErrInvalid)
		}
		capability, capabilityErr := adapterCapability(adapter)
		if capabilityErr != nil {
			return Plan{}, Result{}, capabilityErr
		}
		capabilities[i] = capability
	}
	plan, err = Select(request, capabilities)
	if err != nil {
		return Plan{}, Result{}, err
	}
	selected := -1
	for i, capability := range capabilities {
		if capability.Method == plan.Method {
			selected = i
			break
		}
	}
	if selected < 0 {
		return Plan{}, Result{}, ErrAdapter
	}
	request = cloneRequest(request)
	// Capability inspection and selection may take time in a future adapter
	// integration. Recheck the caller boundary immediately before invocation so
	// cancellation after selection cannot start a native or mutating action.
	if contextErr, panicked := safeContextErr(ctx); panicked {
		return Plan{}, Result{}, fmt.Errorf("%w: context inspection failed", ErrInvalid)
	} else if contextErr != nil {
		return Plan{}, Result{}, contextErr
	}
	currentCapability, capabilityErr := adapterCapability(adapters[selected])
	if capabilityErr != nil {
		return Plan{}, Result{}, capabilityErr
	}
	if err := currentCapability.Validate(); err != nil {
		return Plan{}, Result{}, err
	}
	// Bind invocation to the complete capability snapshot, not only the fields
	// used to choose the method. A capability detail change can indicate that
	// the adapter's session or target changed after selection; accepting it
	// would make the plan describe a different boundary than the one reviewed.
	if currentCapability != capabilities[selected] || currentCapability.Method != plan.Method || !currentCapability.Available || currentCapability.Consent != ConsentGranted {
		return Plan{}, Result{}, ErrUnavailable
	}
	// Capability revalidation may also take time in a future adapter
	// integration. Keep the final context check immediately adjacent to
	// invocation so consent withdrawal and cancellation cannot race into an
	// action after the last policy check.
	if contextErr, panicked := safeContextErr(ctx); panicked {
		return Plan{}, Result{}, fmt.Errorf("%w: context inspection failed", ErrInvalid)
	} else if contextErr != nil {
		return Plan{}, Result{}, contextErr
	}
	// The selected plan contains a pointer-bearing visual target. Give the
	// adapter its own copy so a malformed implementation cannot mutate the
	// policy decision returned to the caller.
	invocationPlan := clonePlan(plan)
	result, err = invokeAdapter(ctx, adapters[selected], request, invocationPlan)
	if err != nil {
		return Plan{}, Result{}, err
	}
	// An adapter may finish an operation after its context is canceled if the
	// platform API does not provide prompt cancellation. Do not let that stale
	// result cross the policy boundary; the adapter remains responsible for
	// stopping its own side effects when cancellation is supported.
	if contextErr, panicked := safeContextErr(ctx); panicked {
		return Plan{}, Result{}, fmt.Errorf("%w: context inspection failed", ErrInvalid)
	} else if contextErr != nil {
		return Plan{}, Result{}, contextErr
	}
	// Do not let a malformed or terminal-active adapter result be silently
	// normalized by a later JSON or logging boundary. The adapter owns the
	// operation, but its result is still untrusted cross-boundary data.
	if err := validateOutput(result.Output); err != nil {
		if errors.Is(err, ErrOutputTooLarge) {
			return Plan{}, Result{}, err
		}
		return Plan{}, Result{}, ErrAdapter
	}
	if err := validateResultEvidence(result.Evidence); err != nil {
		if errors.Is(err, ErrOutputTooLarge) {
			return Plan{}, Result{}, err
		}
		return Plan{}, Result{}, ErrAdapter
	}
	if err := ValidateVisualEvidence(plan, result.Evidence); err != nil {
		return Plan{}, Result{}, err
	}
	return plan, result, nil
}

// validateExecutionContext is the shared entry preflight for every execution
// boundary, including AdapterRegistry. It must run before any adapter
// capability inspection so cancellation and malformed caller contexts cannot
// trigger adapter-owned code.
func validateExecutionContext(ctx context.Context) error {
	if nilContext(ctx) {
		return fmt.Errorf("%w: context is required", ErrInvalid)
	}
	if contextErr, panicked := safeContextErr(ctx); panicked {
		return fmt.Errorf("%w: context inspection failed", ErrInvalid)
	} else if contextErr != nil {
		return contextErr
	}
	return nil
}

// safeContextErr contains a malformed context implementation that panics
// while reporting cancellation. The execution boundary must fail closed
// before adapter inspection or invocation rather than allowing caller-owned
// context code to crash the process.
func safeContextErr(ctx context.Context) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			err = nil
			panicked = true
		}
	}()
	return normalizeContextErr(ctx.Err()), false
}

// normalizeContextErr keeps caller-owned context implementations from
// injecting arbitrary error text or non-cancellation state into the shared
// interaction boundary. The context package contract defines these two
// cancellation sentinels; wrapped forms are reduced to the canonical value.
func normalizeContextErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return fmt.Errorf("%w: unsupported context cancellation state", ErrInvalid)
	}
}

// nilContext rejects both a literal nil context and an interface containing a
// nil pointer. Calling Err on the latter can panic before an adapter is
// selected, so the execution boundary treats both forms as malformed input.
func nilContext(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	v := reflect.ValueOf(ctx)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// nilAdapter rejects both a literal nil adapter and an interface containing a
// nil pointer. A typed-nil adapter may expose methods that tolerate a nil
// receiver, but it is still not a usable capability or execution boundary.
func nilAdapter(adapter Adapter) bool {
	if adapter == nil {
		return true
	}
	v := reflect.ValueOf(adapter)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func adapterCapability(adapter Adapter) (capability Capability, err error) {
	defer func() {
		if recover() != nil {
			capability = Capability{}
			err = ErrAdapter
		}
	}()
	capability = adapter.Capability()
	return capability, nil
}

func invokeAdapter(ctx context.Context, adapter Adapter, request Request, plan Plan) (result Result, err error) {
	defer func() {
		if recover() != nil {
			result = Result{}
			err = ErrAdapter
		}
	}()
	result, err = adapter.Execute(ctx, request, plan)
	if err != nil {
		if errors.Is(err, errRegistryHandoff) {
			return Result{}, ErrUnavailable
		}
		return Result{}, fmt.Errorf("%w", ErrAdapter)
	}
	return result, nil
}

func cloneRequest(request Request) Request {
	if request.Target == nil {
		return request
	}
	copy := *request.Target
	request.Target = &copy
	return request
}

func clonePlan(plan Plan) Plan {
	if plan.Target == nil {
		return plan
	}
	copy := *plan.Target
	plan.Target = &copy
	return plan
}

func (request Request) validate() error {
	if err := validateText(request.Operation, maxOperationBytes, false); err != nil {
		return fmt.Errorf("%w: operation: %v", ErrInvalid, err)
	}
	// A target remains part of the adapter request even when a higher-priority
	// non-visual method is selected. Validate it before selection so an API,
	// terminal, or accessibility adapter never receives unbounded or deceptive
	// target metadata merely because visual execution was not chosen.
	if request.Target != nil {
		if err := request.Target.validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateSelectionRequest(request Request) error {
	if err := request.validate(); err != nil {
		return err
	}
	if request.SecurityDialog {
		return ErrSecurityDialog
	}
	return nil
}

func (capability Capability) validate() error {
	if capability.ownershipDrift {
		return ErrUnavailable
	}
	if !isMethod(capability.Method) {
		return fmt.Errorf("%w: unknown adapter method", ErrInvalid)
	}
	switch capability.Consent {
	case ConsentUnknown, ConsentRequired, ConsentGranted, ConsentDenied:
	default:
		return fmt.Errorf("%w: unknown consent state", ErrInvalid)
	}
	if err := validateText(capability.Detail, maxDetailBytes, true); err != nil {
		return fmt.Errorf("%w: capability detail: %v", ErrInvalid, err)
	}
	return nil
}

func (target VisualTarget) validate() error {
	if err := validateText(target.Label, maxTargetLabelBytes, true); err != nil {
		return fmt.Errorf("%w: target label: %v", ErrVisualTarget, err)
	}
	if target.ScreenWidth <= 0 || target.ScreenHeight <= 0 || target.ScreenWidth > maxScreenDimension || target.ScreenHeight > maxScreenDimension {
		return fmt.Errorf("%w: screen bounds", ErrVisualTarget)
	}
	if target.X < 0 || target.Y < 0 || target.Width <= 0 || target.Height <= 0 {
		return fmt.Errorf("%w: target rectangle", ErrVisualTarget)
	}
	if target.X >= target.ScreenWidth || target.Y >= target.ScreenHeight || target.Width > target.ScreenWidth-target.X || target.Height > target.ScreenHeight-target.Y {
		return fmt.Errorf("%w: target outside screen", ErrVisualTarget)
	}
	return nil
}

func validateEvidenceReference(value string) error {
	return validateText(value, maxEvidenceRefBytes, false)
}

func validateResultEvidence(evidence VisualEvidence) error {
	for _, reference := range []string{evidence.Before, evidence.After} {
		if reference == "" {
			continue
		}
		if len(reference) > maxEvidenceRefBytes {
			return ErrOutputTooLarge
		}
		if err := validateEvidenceReference(reference); err != nil {
			return err
		}
	}
	return nil
}

func validateOutput(value string) error {
	if !utf8.ValidString(value) {
		return errors.New("output is not valid UTF-8")
	}
	if len(value) > maxOutputBytes {
		return ErrOutputTooLarge
	}
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return errors.New("output contains a control character")
		}
		// Format characters include bidi overrides and zero-width controls that
		// can make bounded logs display a different action than was returned.
		if isUnsafeInteractionSeparator(r) {
			return errors.New("output contains a Unicode layout character")
		}
		value = value[size:]
	}
	return nil
}

func validateText(value string, maxBytes int, allowEmpty bool) error {
	if !utf8.ValidString(value) {
		return errors.New("text is not valid UTF-8")
	}
	if !allowEmpty && value == "" {
		return errors.New("text is required")
	}
	if len(value) > maxBytes {
		return fmt.Errorf("text exceeds %d bytes", maxBytes)
	}
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if unicode.IsControl(r) {
			return errors.New("text contains a Unicode control character")
		}
		// Format characters include bidi overrides and zero-width controls that
		// can make bounded policy metadata display differently from its value.
		if isUnsafeInteractionSeparator(r) {
			return errors.New("text contains a Unicode layout character")
		}
		value = value[size:]
	}
	return nil
}

// isUnsafeInteractionSeparator rejects Unicode format and line/paragraph
// separator characters from bounded policy text and adapter output. Format
// characters can make a value render differently from its bytes; line and
// paragraph separators can create a new visual/logical record while remaining
// valid UTF-8 and are not covered by unicode.IsControl.
func isUnsafeInteractionSeparator(value rune) bool {
	return unicode.Is(unicode.Cf, value) || unicode.Is(unicode.Zl, value) || unicode.Is(unicode.Zp, value)
}

func isMethod(method Method) bool {
	for _, known := range methodOrder {
		if method == known {
			return true
		}
	}
	return false
}
