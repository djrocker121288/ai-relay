// Package workflow contains the side-effect-free P8 workflow definition
// boundary. It validates bounded triggers, approvals, retries, artifacts, and
// compensation declarations, then produces a deterministic DAG plan. It does
// not execute steps, persist state, or contact a provider.
package workflow

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxIDBytes                 = 128
	maxNameBytes               = 256
	maxSteps                   = 256
	maxDependencies            = 32
	maxApprovalScopes          = 8
	maxRetryAttempts           = 100
	maxRetryDelay              = 24 * time.Hour
	minScheduleInterval        = time.Minute
	maxScheduleInterval        = 7 * 24 * time.Hour
	minArtifactRetention       = time.Hour
	maxArtifactRetention       = 90 * 24 * time.Hour
	minArtifactBytes     int64 = 1024
	maxArtifactBytes     int64 = 1 << 30
)

var ErrInvalid = errors.New("invalid workflow definition")

// Definition describes a workflow without granting it execution authority.
// Exactly one trigger mode must be configured: Event or Every.
type Definition struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Trigger   Trigger        `json:"trigger"`
	Steps     []Step         `json:"steps"`
	Artifacts ArtifactPolicy `json:"artifacts,omitempty"`
}

type Trigger struct {
	Event string        `json:"event,omitempty"`
	Every time.Duration `json:"every,omitempty"`
}

type Step struct {
	ID           string         `json:"id"`
	Action       string         `json:"action"`
	DependsOn    []string       `json:"depends_on,omitempty"`
	Retry        RetryPolicy    `json:"retry,omitempty"`
	Approval     ApprovalPolicy `json:"approval,omitempty"`
	Compensation *Compensation  `json:"compensation,omitempty"`
}

type RetryPolicy struct {
	MaxAttempts uint32        `json:"max_attempts,omitempty"`
	InitialWait time.Duration `json:"initial_wait,omitempty"`
	MaxWait     time.Duration `json:"max_wait,omitempty"`
}

type ApprovalPolicy struct {
	Required bool     `json:"required,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}

type Compensation struct {
	Action string `json:"action"`
}

type ArtifactPolicy struct {
	Retention time.Duration `json:"retention,omitempty"`
	MaxBytes  int64         `json:"max_bytes,omitempty"`
}

// Plan is a validated, deterministic execution description. The planner does
// not run either list. Compensation is ordered in reverse topological order;
// an executor should include only compensations for steps that actually ran.
type Plan struct {
	Steps        []Step `json:"steps"`
	Compensation []Step `json:"compensation,omitempty"`
}

// CompensationsFor returns compensations only for steps that the caller
// reports as completed. Completed IDs may be supplied in any order, but they
// must identify unique steps in this plan. The result follows the plan's
// reverse topological order and contains copies. This helper only applies
// policy; it does not execute, persist, or authorize compensation work.
func (p Plan) CompensationsFor(completed []string) ([]Step, error) {
	if len(p.Steps) == 0 || len(p.Steps) > maxSteps {
		return nil, fmt.Errorf("%w: plan steps must contain 1-%d items", ErrInvalid, maxSteps)
	}
	steps := make(map[string]Step, len(p.Steps))
	for _, step := range p.Steps {
		if err := validatePlannedStep(step); err != nil {
			return nil, err
		}
		if _, exists := steps[step.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate planned step %q", ErrInvalid, step.ID)
		}
		steps[step.ID] = step
	}
	for _, step := range p.Steps {
		for _, dependency := range step.DependsOn {
			if _, exists := steps[dependency]; !exists {
				return nil, fmt.Errorf("%w: planned step %q depends on missing step %q", ErrInvalid, step.ID, dependency)
			}
		}
	}
	ordered, err := topologicalSteps(steps)
	if err != nil {
		return nil, err
	}
	for index, step := range ordered {
		if p.Steps[index].ID != step.ID {
			return nil, fmt.Errorf("%w: planned steps are not in deterministic order", ErrInvalid)
		}
	}

	completedSet := make(map[string]struct{}, len(completed))
	for _, id := range completed {
		if err := validID("completed step", id); err != nil {
			return nil, err
		}
		if _, exists := steps[id]; !exists {
			return nil, fmt.Errorf("%w: completed step %q is not in the plan", ErrInvalid, id)
		}
		if _, duplicate := completedSet[id]; duplicate {
			return nil, fmt.Errorf("%w: completed step %q is repeated", ErrInvalid, id)
		}
		completedSet[id] = struct{}{}
	}

	compensations := make([]Step, 0, len(completed))
	for index := len(p.Steps) - 1; index >= 0; index-- {
		step := p.Steps[index]
		if _, completed := completedSet[step.ID]; !completed || step.Compensation == nil {
			continue
		}
		compensations = append(compensations, cloneStep(step))
	}
	return compensations, nil
}

// MatchesEvent reports whether event activates this definition's event
// trigger. It validates the complete definition before evaluating the event,
// so a caller cannot use trigger matching to bypass workflow policy checks.
// Interval-triggered definitions never match an event.
func (d Definition) MatchesEvent(event string) (bool, error) {
	if err := d.Validate(); err != nil {
		return false, err
	}
	if event != "" {
		if err := validText("event", event, maxIDBytes); err != nil {
			return false, err
		}
	}
	if d.Trigger.Event == "" || event == "" {
		return false, nil
	}
	return d.Trigger.Event == event, nil
}

// ScheduleDue reports whether an interval-triggered definition is due at now.
// A zero lastRun means the schedule has never run and is immediately due. A
// clock that moves backwards is rejected rather than causing an early run.
// Event-triggered definitions are never due on a schedule.
func (d Definition) ScheduleDue(lastRun, now time.Time) (bool, error) {
	if err := d.Validate(); err != nil {
		return false, err
	}
	if d.Trigger.Every == 0 {
		return false, nil
	}
	if now.IsZero() {
		return false, fmt.Errorf("%w: current time is required", ErrInvalid)
	}
	if !lastRun.IsZero() && now.Before(lastRun) {
		return false, fmt.Errorf("%w: current time precedes last run", ErrInvalid)
	}
	if lastRun.IsZero() {
		return true, nil
	}
	return now.Sub(lastRun) >= d.Trigger.Every, nil
}

// Delay returns the bounded exponential wait before a 1-based retry number.
// MaxAttempts includes the initial attempt, so retryNumber must be less than
// the normalized MaxAttempts. The calculation is saturating and cannot
// overflow time.Duration.
func (p RetryPolicy) Delay(retryNumber uint32) (time.Duration, error) {
	if err := validateRetry(p); err != nil {
		return 0, fmt.Errorf("%w: retry policy: %v", ErrInvalid, err)
	}
	attempts := normalizedMaxAttempts(p)
	if retryNumber == 0 || retryNumber >= attempts {
		return 0, fmt.Errorf("%w: retry number must be between 1 and %d", ErrInvalid, attempts-1)
	}

	delay := p.InitialWait
	for step := uint32(1); step < retryNumber; step++ {
		if delay > maxRetryDelay/2 {
			delay = maxRetryDelay
			break
		}
		delay *= 2
	}
	limit := p.MaxWait
	if limit == 0 {
		limit = maxRetryDelay
	}
	if delay > limit {
		delay = limit
	}
	return delay, nil
}

// CanRetry reports whether a completed 1-based attempt may be retried under
// this policy. MaxAttempts includes the initial attempt, so attempt 1 may be
// retried when MaxAttempts is greater than 1. Attempt zero is malformed input;
// callers must not use it to bypass the initial-attempt accounting.
func (p RetryPolicy) CanRetry(attempt uint32) (bool, error) {
	if err := validateRetry(p); err != nil {
		return false, fmt.Errorf("%w: retry policy: %v", ErrInvalid, err)
	}
	if attempt == 0 {
		return false, fmt.Errorf("%w: attempt must be at least 1", ErrInvalid)
	}
	return attempt < normalizedMaxAttempts(p), nil
}

func normalizedMaxAttempts(policy RetryPolicy) uint32 {
	if policy.MaxAttempts == 0 {
		return 1
	}
	return policy.MaxAttempts
}

// SatisfiedBy reports whether a bounded, already-authenticated approval grant
// contains every scope required by this policy. It evaluates policy only: it
// does not authenticate the grant, check its issuer or expiry, or persist an
// approval. Unknown additional scopes are allowed so a caller can pass the
// complete grant rather than pre-filtering it.
func (p ApprovalPolicy) SatisfiedBy(granted []string) (bool, error) {
	if err := validateApproval(p); err != nil {
		return false, fmt.Errorf("%w: approval policy: %v", ErrInvalid, err)
	}
	if len(granted) > maxApprovalScopes {
		return false, fmt.Errorf("%w: approval grant contains more than %d scopes", ErrInvalid, maxApprovalScopes)
	}
	seen := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		if err := validID("granted approval scope", scope); err != nil {
			return false, err
		}
		if _, duplicate := seen[scope]; duplicate {
			return false, fmt.Errorf("%w: duplicate granted approval scope %q", ErrInvalid, scope)
		}
		seen[scope] = struct{}{}
	}
	if !p.Required {
		return true, nil
	}
	for _, required := range p.Scopes {
		if _, present := seen[required]; !present {
			return false, nil
		}
	}
	return true, nil
}

// AllowsSize reports whether a non-negative artifact size fits this policy.
// A zero MaxBytes means that the definition did not configure a size limit.
// The helper only evaluates policy; it does not read, write, or retain an
// artifact.
func (p ArtifactPolicy) AllowsSize(size int64) (bool, error) {
	if err := validateArtifacts(p); err != nil {
		return false, err
	}
	if size < 0 {
		return false, fmt.Errorf("%w: artifact size cannot be negative", ErrInvalid)
	}
	return p.MaxBytes == 0 || size <= p.MaxBytes, nil
}

// RetentionDue reports whether an artifact created at createdAt has reached
// this policy's retention boundary at now. A zero Retention means retention
// is not configured and therefore never expires. A caller must supply valid,
// ordered timestamps when retention is configured.
func (p ArtifactPolicy) RetentionDue(createdAt, now time.Time) (bool, error) {
	if err := validateArtifacts(p); err != nil {
		return false, err
	}
	if p.Retention == 0 {
		return false, nil
	}
	if createdAt.IsZero() || now.IsZero() {
		return false, fmt.Errorf("%w: artifact timestamps are required", ErrInvalid)
	}
	if now.Before(createdAt) {
		return false, fmt.Errorf("%w: current time precedes artifact creation", ErrInvalid)
	}
	return now.Sub(createdAt) >= p.Retention, nil
}

// Validate checks all bounded workflow policy and DAG invariants.
func (d Definition) Validate() error {
	if err := validID("workflow", d.ID); err != nil {
		return err
	}
	if err := validText("workflow name", d.Name, maxNameBytes); err != nil {
		return err
	}
	if err := validateTrigger(d.Trigger); err != nil {
		return err
	}
	if len(d.Steps) == 0 || len(d.Steps) > maxSteps {
		return fmt.Errorf("%w: steps must contain 1-%d items", ErrInvalid, maxSteps)
	}
	if err := validateArtifacts(d.Artifacts); err != nil {
		return err
	}

	steps := make(map[string]Step, len(d.Steps))
	for _, step := range d.Steps {
		if err := validID("step", step.ID); err != nil {
			return err
		}
		if _, exists := steps[step.ID]; exists {
			return fmt.Errorf("%w: duplicate step %q", ErrInvalid, step.ID)
		}
		if err := validText("step action", step.Action, maxNameBytes); err != nil {
			return err
		}
		if err := validateRetry(step.Retry); err != nil {
			return fmt.Errorf("%w: step %q retry: %v", ErrInvalid, step.ID, err)
		}
		if err := validateApproval(step.Approval); err != nil {
			return fmt.Errorf("%w: step %q approval: %v", ErrInvalid, step.ID, err)
		}
		if step.Compensation != nil {
			if err := validText("compensation action", step.Compensation.Action, maxNameBytes); err != nil {
				return fmt.Errorf("%w: step %q compensation: %v", ErrInvalid, step.ID, err)
			}
		}
		if len(step.DependsOn) > maxDependencies {
			return fmt.Errorf("%w: step %q has too many dependencies", ErrInvalid, step.ID)
		}
		seen := make(map[string]struct{}, len(step.DependsOn))
		for _, dependency := range step.DependsOn {
			if err := validID("dependency", dependency); err != nil {
				return fmt.Errorf("%w: step %q dependency: %v", ErrInvalid, step.ID, err)
			}
			if dependency == step.ID {
				return fmt.Errorf("%w: step %q depends on itself", ErrInvalid, step.ID)
			}
			if _, duplicate := seen[dependency]; duplicate {
				return fmt.Errorf("%w: step %q repeats dependency %q", ErrInvalid, step.ID, dependency)
			}
			seen[dependency] = struct{}{}
		}
		steps[step.ID] = step
	}
	for _, step := range d.Steps {
		for _, dependency := range step.DependsOn {
			if _, exists := steps[dependency]; !exists {
				return fmt.Errorf("%w: step %q depends on missing step %q", ErrInvalid, step.ID, dependency)
			}
		}
	}
	if _, err := topologicalSteps(steps); err != nil {
		return err
	}
	return nil
}

// Plan validates the definition and returns stable topological and reverse
// compensation orderings. Returned slices and nested policy slices are copies.
func (d Definition) Plan() (Plan, error) {
	if err := d.Validate(); err != nil {
		return Plan{}, err
	}
	steps := make(map[string]Step, len(d.Steps))
	for _, step := range d.Steps {
		steps[step.ID] = normalizeStep(step)
	}
	ordered, err := topologicalSteps(steps)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Steps: make([]Step, 0, len(ordered))}
	for _, step := range ordered {
		plan.Steps = append(plan.Steps, cloneStep(step))
	}
	for index := len(ordered) - 1; index >= 0; index-- {
		if ordered[index].Compensation != nil {
			plan.Compensation = append(plan.Compensation, cloneStep(ordered[index]))
		}
	}
	return plan, nil
}

func validateTrigger(trigger Trigger) error {
	if trigger.Event != "" && trigger.Every != 0 {
		return fmt.Errorf("%w: trigger must use event or interval, not both", ErrInvalid)
	}
	if trigger.Event == "" && trigger.Every == 0 {
		return fmt.Errorf("%w: trigger is required", ErrInvalid)
	}
	if trigger.Event != "" {
		return validText("trigger event", trigger.Event, maxIDBytes)
	}
	if trigger.Every < minScheduleInterval || trigger.Every > maxScheduleInterval {
		return fmt.Errorf("%w: trigger interval must be between %s and %s", ErrInvalid, minScheduleInterval, maxScheduleInterval)
	}
	return nil
}

func validateRetry(policy RetryPolicy) error {
	attempts := policy.MaxAttempts
	if attempts == 0 {
		attempts = 1
	}
	if attempts > maxRetryAttempts {
		return fmt.Errorf("attempts exceed %d", maxRetryAttempts)
	}
	if policy.InitialWait < 0 || policy.MaxWait < 0 {
		return errors.New("waits cannot be negative")
	}
	if policy.InitialWait > maxRetryDelay || policy.MaxWait > maxRetryDelay {
		return fmt.Errorf("waits exceed %s", maxRetryDelay)
	}
	if attempts > 1 && policy.InitialWait == 0 {
		return errors.New("initial wait is required when retries are enabled")
	}
	if policy.MaxWait != 0 && policy.MaxWait < policy.InitialWait {
		return errors.New("max wait cannot be less than initial wait")
	}
	return nil
}

func validateApproval(policy ApprovalPolicy) error {
	if len(policy.Scopes) > maxApprovalScopes {
		return fmt.Errorf("approval scopes exceed %d", maxApprovalScopes)
	}
	if !policy.Required && len(policy.Scopes) != 0 {
		return errors.New("approval scopes require approval")
	}
	seen := make(map[string]struct{}, len(policy.Scopes))
	for _, scope := range policy.Scopes {
		if err := validID("approval scope", scope); err != nil {
			return err
		}
		if _, duplicate := seen[scope]; duplicate {
			return fmt.Errorf("duplicate approval scope %q", scope)
		}
		seen[scope] = struct{}{}
	}
	if policy.Required && len(policy.Scopes) == 0 {
		return errors.New("required approval has no scopes")
	}
	return nil
}

func validateArtifacts(policy ArtifactPolicy) error {
	if policy.Retention != 0 && (policy.Retention < minArtifactRetention || policy.Retention > maxArtifactRetention) {
		return fmt.Errorf("%w: artifact retention must be between %s and %s", ErrInvalid, minArtifactRetention, maxArtifactRetention)
	}
	if policy.MaxBytes != 0 && (policy.MaxBytes < minArtifactBytes || policy.MaxBytes > maxArtifactBytes) {
		return fmt.Errorf("%w: artifact limit must be between %d and %d bytes", ErrInvalid, minArtifactBytes, maxArtifactBytes)
	}
	return nil
}

func validatePlannedStep(step Step) error {
	if err := validID("planned step", step.ID); err != nil {
		return err
	}
	if err := validText("planned step action", step.Action, maxNameBytes); err != nil {
		return err
	}
	if err := validateRetry(step.Retry); err != nil {
		return fmt.Errorf("%w: planned step %q retry: %v", ErrInvalid, step.ID, err)
	}
	if err := validateApproval(step.Approval); err != nil {
		return fmt.Errorf("%w: planned step %q approval: %v", ErrInvalid, step.ID, err)
	}
	if step.Compensation != nil {
		if err := validText("planned compensation action", step.Compensation.Action, maxNameBytes); err != nil {
			return fmt.Errorf("%w: planned step %q compensation: %v", ErrInvalid, step.ID, err)
		}
	}
	if len(step.DependsOn) > maxDependencies {
		return fmt.Errorf("%w: planned step %q has too many dependencies", ErrInvalid, step.ID)
	}
	for index, dependency := range step.DependsOn {
		if err := validID("planned dependency", dependency); err != nil {
			return fmt.Errorf("%w: planned step %q dependency: %v", ErrInvalid, step.ID, err)
		}
		if dependency == step.ID {
			return fmt.Errorf("%w: planned step %q depends on itself", ErrInvalid, step.ID)
		}
		if index > 0 && step.DependsOn[index-1] >= dependency {
			return fmt.Errorf("%w: planned step %q dependencies are not sorted and unique", ErrInvalid, step.ID)
		}
	}
	for index, scope := range step.Approval.Scopes {
		if index > 0 && step.Approval.Scopes[index-1] >= scope {
			return fmt.Errorf("%w: planned step %q approval scopes are not sorted and unique", ErrInvalid, step.ID)
		}
	}
	if step.Retry.MaxAttempts == 0 {
		return fmt.Errorf("%w: planned step %q retry attempts are not normalized", ErrInvalid, step.ID)
	}
	return nil
}

func topologicalSteps(steps map[string]Step) ([]Step, error) {
	indegree := make(map[string]int, len(steps))
	children := make(map[string][]string, len(steps))
	for id, step := range steps {
		indegree[id] = len(step.DependsOn)
		for _, dependency := range step.DependsOn {
			children[dependency] = append(children[dependency], id)
		}
	}
	ready := make([]string, 0, len(steps))
	for id, count := range indegree {
		if count == 0 {
			ready = append(ready, id)
		}
	}
	sort.Strings(ready)
	ordered := make([]Step, 0, len(steps))
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		ordered = append(ordered, steps[id])
		for _, child := range children[id] {
			indegree[child]--
			if indegree[child] == 0 {
				ready = append(ready, child)
			}
		}
		sort.Strings(ready)
	}
	if len(ordered) != len(steps) {
		return nil, fmt.Errorf("%w: workflow step graph contains a cycle", ErrInvalid)
	}
	return ordered, nil
}

func normalizeStep(step Step) Step {
	if step.Retry.MaxAttempts == 0 {
		step.Retry.MaxAttempts = 1
	}
	step.DependsOn = append([]string(nil), step.DependsOn...)
	sort.Strings(step.DependsOn)
	step.Approval.Scopes = append([]string(nil), step.Approval.Scopes...)
	sort.Strings(step.Approval.Scopes)
	return step
}

func cloneStep(step Step) Step {
	step.DependsOn = append([]string(nil), step.DependsOn...)
	step.Approval.Scopes = append([]string(nil), step.Approval.Scopes...)
	if step.Compensation != nil {
		compensation := *step.Compensation
		step.Compensation = &compensation
	}
	return step
}

func validID(kind, value string) error {
	return validText(kind, value, maxIDBytes)
}

func validText(kind, value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: %s is empty, oversized, malformed, or padded", ErrInvalid, kind)
	}
	for _, r := range value {
		if unicode.IsControl(r) || isUnsafeWorkflowSeparator(r) {
			return fmt.Errorf("%w: %s contains a control, format, or line-separator character", ErrInvalid, kind)
		}
	}
	return nil
}

// isUnsafeWorkflowSeparator rejects Unicode format and line/paragraph
// separator characters from bounded workflow metadata. Format characters can
// make a value render differently from its bytes; line and paragraph
// separators can create a new visual/logical record while remaining valid
// UTF-8 and are not covered by unicode.IsControl.
func isUnsafeWorkflowSeparator(value rune) bool {
	return unicode.Is(unicode.Cf, value) || unicode.Is(unicode.Zl, value) || unicode.Is(unicode.Zp, value)
}
