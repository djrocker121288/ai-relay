package workflow

import (
	"errors"
	"testing"
	"time"
)

func TestPlanIsDeterministicAndReversesCompensation(t *testing.T) {
	d := Definition{
		ID:        "deploy",
		Name:      "bounded deploy",
		Trigger:   Trigger{Event: "approved"},
		Artifacts: ArtifactPolicy{Retention: 24 * time.Hour, MaxBytes: 1 << 20},
		Steps: []Step{
			{ID: "finish", Action: "finish", DependsOn: []string{"verify"}, Compensation: &Compensation{Action: "undo-finish"}},
			{ID: "verify", Action: "verify", DependsOn: []string{"build"}},
			{ID: "build", Action: "build", Compensation: &Compensation{Action: "undo-build"}},
			{ID: "announce", Action: "announce", DependsOn: []string{"build"}},
		},
	}
	plan, err := d.Plan()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		got = append(got, step.ID)
	}
	want := []string{"build", "announce", "verify", "finish"}
	if len(got) != len(want) {
		t.Fatalf("step order=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step order=%v, want %v", got, want)
		}
	}
	if len(plan.Compensation) != 2 || plan.Compensation[0].ID != "finish" || plan.Compensation[1].ID != "build" {
		t.Fatalf("compensation order=%v, want finish/build", plan.Compensation)
	}
	plan.Steps[2].DependsOn[0] = "mutated"
	if d.Steps[1].DependsOn[0] != "build" {
		t.Fatal("planner changed definition dependencies")
	}
}

func TestPlanCompensationsForCompletedStepsIsBoundedAndDeterministic(t *testing.T) {
	d := Definition{
		ID:      "compensate",
		Name:    "compensate",
		Trigger: Trigger{Event: "approved"},
		Steps: []Step{
			{ID: "finish", Action: "finish", DependsOn: []string{"verify"}, Compensation: &Compensation{Action: "undo-finish"}},
			{ID: "verify", Action: "verify", DependsOn: []string{"build"}},
			{ID: "build", Action: "build", Compensation: &Compensation{Action: "undo-build"}},
			{ID: "announce", Action: "announce", DependsOn: []string{"build"}, Compensation: &Compensation{Action: "undo-announce"}},
		},
	}
	plan, err := d.Plan()
	if err != nil {
		t.Fatal(err)
	}
	compensations, err := plan.CompensationsFor([]string{"announce", "build", "finish"})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{compensations[0].ID, compensations[1].ID, compensations[2].ID}; !equalStrings(got, []string{"finish", "announce", "build"}) {
		t.Fatalf("compensation order = %v, want finish/announce/build", got)
	}
	compensations[0].Compensation.Action = "mutated"
	if plan.Steps[3].Compensation.Action == "mutated" {
		t.Fatal("compensation result retained plan-owned pointer")
	}

	for _, tc := range []struct {
		name      string
		completed []string
	}{
		{name: "unknown", completed: []string{"missing"}},
		{name: "duplicate", completed: []string{"build", "build"}},
		{name: "malformed", completed: []string{"build\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := plan.CompensationsFor(tc.completed); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
	if got, err := plan.CompensationsFor(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty completion set = %#v, %v; want empty result", got, err)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestValidateRejectsUnsafeOrAmbiguousDefinitions(t *testing.T) {
	cases := []Definition{
		{ID: "cycle", Name: "cycle", Trigger: Trigger{Every: time.Minute}, Steps: []Step{
			{ID: "a", Action: "a", DependsOn: []string{"b"}},
			{ID: "b", Action: "b", DependsOn: []string{"a"}},
		}},
		{ID: "duplicate", Name: "duplicate", Trigger: Trigger{Event: "go"}, Steps: []Step{
			{ID: "a", Action: "a"}, {ID: "a", Action: "again"},
		}},
		{ID: "missing", Name: "missing", Trigger: Trigger{Event: "go"}, Steps: []Step{{ID: "a", Action: "a", DependsOn: []string{"nope"}}}},
		{ID: "ambiguous", Name: "ambiguous", Trigger: Trigger{Event: "go", Every: time.Minute}, Steps: []Step{{ID: "a", Action: "a"}}},
		{ID: "approval", Name: "approval", Trigger: Trigger{Event: "go"}, Steps: []Step{{ID: "a", Action: "a", Approval: ApprovalPolicy{Scopes: []string{"ops"}}}}},
	}
	for _, tc := range cases {
		if err := tc.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("definition %q error=%v, want ErrInvalid", tc.ID, err)
		}
	}
}

func TestValidateBoundsRetryScheduleAndArtifacts(t *testing.T) {
	base := func() Definition {
		return Definition{ID: "bounded", Name: "bounded", Trigger: Trigger{Event: "go"}, Steps: []Step{{ID: "step", Action: "run"}}}
	}
	cases := []Definition{
		func() Definition { d := base(); d.Trigger = Trigger{Every: 30 * time.Second}; return d }(),
		func() Definition { d := base(); d.Steps[0].Retry = RetryPolicy{MaxAttempts: 2}; return d }(),
		func() Definition {
			d := base()
			d.Steps[0].Retry = RetryPolicy{MaxAttempts: 2, InitialWait: time.Second, MaxWait: 500 * time.Millisecond}
			return d
		}(),
		func() Definition { d := base(); d.Artifacts = ArtifactPolicy{Retention: 30 * time.Minute}; return d }(),
		func() Definition { d := base(); d.Artifacts = ArtifactPolicy{MaxBytes: 512}; return d }(),
	}
	for index, tc := range cases {
		if err := tc.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d error=%v, want ErrInvalid", index, err)
		}
	}
}

func TestValidateRejectsUnicodeControlCharacters(t *testing.T) {
	base := func() Definition {
		return Definition{
			ID:      "unicode-controls",
			Name:    "unicode controls",
			Trigger: Trigger{Event: "approved"},
			Steps:   []Step{{ID: "step", Action: "run"}},
		}
	}
	cases := []Definition{
		func() Definition { d := base(); d.Name = "unicode\u0085name"; return d }(),
		func() Definition { d := base(); d.Trigger.Event = "approved\u0085event"; return d }(),
		func() Definition { d := base(); d.Steps[0].Action = "run\u0085action"; return d }(),
		func() Definition {
			d := base()
			d.Steps[0].Compensation = &Compensation{Action: "undo\u0085action"}
			return d
		}(),
	}
	for index, definition := range cases {
		if err := definition.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d error=%v, want ErrInvalid", index, err)
		}
	}
}

func TestValidateRejectsUnicodeFormatCharacters(t *testing.T) {
	base := func() Definition {
		return Definition{
			ID:      "unicode-format",
			Name:    "unicode format",
			Trigger: Trigger{Event: "approved"},
			Steps: []Step{{
				ID:     "step",
				Action: "run",
				Approval: ApprovalPolicy{
					Required: true,
					Scopes:   []string{"ops"},
				},
			}},
		}
	}
	cases := []Definition{
		func() Definition { d := base(); d.ID = "unicode\u200Bformat"; return d }(),
		func() Definition { d := base(); d.Name = "unicode\u202Eformat"; return d }(),
		func() Definition { d := base(); d.Trigger.Event = "approved\u200Bevent"; return d }(),
		func() Definition { d := base(); d.Steps[0].ID = "ste\u202Ep"; return d }(),
		func() Definition { d := base(); d.Steps[0].Action = "run\u200Baction"; return d }(),
		func() Definition {
			d := base()
			d.Steps[0].DependsOn = []string{"other"}
			d.Steps = append(d.Steps, Step{ID: "other", Action: "other"})
			d.Steps[0].DependsOn[0] = "ot\u202Eher"
			return d
		}(),
		func() Definition {
			d := base()
			d.Steps[0].Compensation = &Compensation{Action: "undo\u200Baction"}
			return d
		}(),
		func() Definition {
			d := base()
			d.Steps[0].Approval.Scopes = []string{"op\u202Es"}
			return d
		}(),
	}
	for index, definition := range cases {
		if err := definition.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d error=%v, want ErrInvalid", index, err)
		}
	}
}

func TestValidateRejectsUnicodeLineAndParagraphSeparators(t *testing.T) {
	base := Definition{
		ID:      "unicode-separators",
		Name:    "unicode separators",
		Trigger: Trigger{Event: "approved"},
		Steps:   []Step{{ID: "step", Action: "run"}},
	}
	cases := []struct {
		name   string
		mutate func(*Definition)
	}{
		{name: "name line separator", mutate: func(d *Definition) { d.Name = "workflow\u2028name" }},
		{name: "event paragraph separator", mutate: func(d *Definition) { d.Trigger.Event = "approved\u2029event" }},
		{name: "action line separator", mutate: func(d *Definition) { d.Steps[0].Action = "run\u2028action" }},
		{name: "approval scope paragraph separator", mutate: func(d *Definition) {
			d.Steps[0].Approval = ApprovalPolicy{Required: true, Scopes: []string{"ops\u2029scope"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			definition := base
			tc.mutate(&definition)
			if err := definition.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("definition error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestPlanNormalizesDefaultsWithoutMutatingInput(t *testing.T) {
	d := Definition{ID: "defaults", Name: "defaults", Trigger: Trigger{Event: "go"}, Steps: []Step{{ID: "step", Action: "run"}}}
	plan, err := d.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Steps[0].Retry.MaxAttempts != 1 {
		t.Fatalf("max attempts=%d, want 1", plan.Steps[0].Retry.MaxAttempts)
	}
	if d.Steps[0].Retry.MaxAttempts != 0 {
		t.Fatal("plan mutated the input retry policy")
	}
}

func TestTriggerEvaluationIsValidatedAndDeterministic(t *testing.T) {
	eventDefinition := Definition{
		ID:      "event",
		Name:    "event",
		Trigger: Trigger{Event: "approved"},
		Steps:   []Step{{ID: "step", Action: "run"}},
	}
	matched, err := eventDefinition.MatchesEvent("approved")
	if err != nil || !matched {
		t.Fatalf("matching event=(%t, %v), want true", matched, err)
	}
	matched, err = eventDefinition.MatchesEvent("other")
	if err != nil || matched {
		t.Fatalf("non-matching event=(%t, %v), want false", matched, err)
	}
	if matched, err := eventDefinition.ScheduleDue(time.Time{}, time.Now()); err != nil || matched {
		t.Fatalf("event schedule=(%t, %v), want false", matched, err)
	}

	intervalDefinition := eventDefinition
	intervalDefinition.ID = "interval"
	intervalDefinition.Trigger = Trigger{Every: time.Hour}
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	if due, err := intervalDefinition.ScheduleDue(time.Time{}, now); err != nil || !due {
		t.Fatalf("first interval=(%t, %v), want true", due, err)
	}
	if due, err := intervalDefinition.ScheduleDue(now.Add(-time.Minute), now); err != nil || due {
		t.Fatalf("early interval=(%t, %v), want false", due, err)
	}
	if due, err := intervalDefinition.ScheduleDue(now.Add(-time.Hour), now); err != nil || !due {
		t.Fatalf("elapsed interval=(%t, %v), want true", due, err)
	}
	if _, err := intervalDefinition.ScheduleDue(now.Add(time.Minute), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("backwards clock error=%v, want ErrInvalid", err)
	}
	if _, err := intervalDefinition.ScheduleDue(time.Time{}, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero clock error=%v, want ErrInvalid", err)
	}
	if _, err := intervalDefinition.MatchesEvent("\n"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed event error=%v, want ErrInvalid", err)
	}
}

func TestRetryDelayIsBoundedAndRejectsNonRetries(t *testing.T) {
	policy := RetryPolicy{MaxAttempts: 5, InitialWait: time.Second, MaxWait: 3 * time.Second}
	for retry, want := range map[uint32]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 3 * time.Second, 4: 3 * time.Second} {
		got, err := policy.Delay(retry)
		if err != nil || got != want {
			t.Errorf("retry %d delay=%s, error=%v; want %s", retry, got, err, want)
		}
	}
	for _, retry := range []uint32{0, 5} {
		if _, err := policy.Delay(retry); !errors.Is(err, ErrInvalid) {
			t.Errorf("retry %d error=%v, want ErrInvalid", retry, err)
		}
	}
	uncapped := RetryPolicy{MaxAttempts: 100, InitialWait: 24 * time.Hour}
	if got, err := uncapped.Delay(99); err != nil || got != maxRetryDelay {
		t.Fatalf("saturated delay=%s, error=%v; want %s", got, err, maxRetryDelay)
	}
	if got, err := (RetryPolicy{}).Delay(1); err == nil || got != 0 {
		t.Fatalf("single-attempt delay=%s, error=%v; want invalid zero delay", got, err)
	}
}

func TestRetryPolicyCanRetryUsesInitialAttemptAccounting(t *testing.T) {
	policy := RetryPolicy{MaxAttempts: 3, InitialWait: time.Second}
	for _, tc := range []struct {
		attempt uint32
		want    bool
	}{
		{attempt: 1, want: true},
		{attempt: 2, want: true},
		{attempt: 3, want: false},
	} {
		got, err := policy.CanRetry(tc.attempt)
		if err != nil || got != tc.want {
			t.Errorf("attempt %d retryable=(%t, %v), want (%t, nil)", tc.attempt, got, err, tc.want)
		}
	}
	if got, err := (RetryPolicy{}).CanRetry(1); err != nil || got {
		t.Fatalf("default policy retryable=(%t, %v), want (false, nil)", got, err)
	}
	if got, err := policy.CanRetry(0); !errors.Is(err, ErrInvalid) || got {
		t.Fatalf("zero attempt retryable=(%t, %v), want (false, ErrInvalid)", got, err)
	}
	if got, err := (RetryPolicy{MaxAttempts: 2, InitialWait: time.Second, MaxWait: -time.Second}).CanRetry(1); !errors.Is(err, ErrInvalid) || got {
		t.Fatalf("invalid policy retryable=(%t, %v), want (false, ErrInvalid)", got, err)
	}
}

func TestApprovalPolicySatisfactionIsBoundedAndDeterministic(t *testing.T) {
	policy := ApprovalPolicy{Required: true, Scopes: []string{"deploy", "ops"}}
	for _, tc := range []struct {
		name    string
		granted []string
		want    bool
		invalid bool
	}{
		{name: "all required scopes", granted: []string{"ops", "deploy", "read"}, want: true},
		{name: "missing required scope", granted: []string{"ops"}, want: false},
		{name: "duplicate grant", granted: []string{"ops", "ops"}, invalid: true},
		{name: "malformed grant", granted: []string{"ops\n"}, invalid: true},
		{name: "too many grants", granted: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := policy.SatisfiedBy(tc.granted)
			if tc.invalid {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("error=%v, want ErrInvalid", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("satisfied=(%t, %v), want (%t, nil)", got, err, tc.want)
			}
		})
	}

	optional := ApprovalPolicy{}
	if got, err := optional.SatisfiedBy(nil); err != nil || !got {
		t.Fatalf("optional satisfaction=(%t, %v), want (true, nil)", got, err)
	}
	if got, err := optional.SatisfiedBy([]string{"read"}); err != nil || !got {
		t.Fatalf("optional extra grant satisfaction=(%t, %v), want (true, nil)", got, err)
	}
	if got, err := (ApprovalPolicy{Required: true}).SatisfiedBy(nil); !errors.Is(err, ErrInvalid) || got {
		t.Fatalf("invalid required policy=(%t, %v), want false and ErrInvalid", got, err)
	}
}

func TestArtifactPolicyAdmissionAndRetentionAreBounded(t *testing.T) {
	policy := ArtifactPolicy{Retention: time.Hour, MaxBytes: 1024}
	for _, tc := range []struct {
		name    string
		size    int64
		want    bool
		invalid bool
	}{
		{name: "empty artifact", size: 0, want: true},
		{name: "at size limit", size: 1024, want: true},
		{name: "over size limit", size: 1025, want: false},
		{name: "negative size", size: -1, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := policy.AllowsSize(tc.size)
			if tc.invalid {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("error=%v, want ErrInvalid", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("allowed=(%t, %v), want (%t, nil)", got, err, tc.want)
			}
		})
	}

	created := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		now     time.Time
		want    bool
		invalid bool
	}{
		{name: "before boundary", now: created.Add(time.Hour - time.Nanosecond), want: false},
		{name: "at boundary", now: created.Add(time.Hour), want: true},
		{name: "after boundary", now: created.Add(2 * time.Hour), want: true},
		{name: "backwards clock", now: created.Add(-time.Nanosecond), invalid: true},
		{name: "missing timestamp", now: time.Time{}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := policy.RetentionDue(created, tc.now)
			if tc.invalid {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("error=%v, want ErrInvalid", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("due=(%t, %v), want (%t, nil)", got, err, tc.want)
			}
		})
	}

	if got, err := (ArtifactPolicy{}).AllowsSize(1 << 62); err != nil || !got {
		t.Fatalf("unlimited size=(%t, %v), want (true, nil)", got, err)
	}
	if got, err := (ArtifactPolicy{}).RetentionDue(time.Time{}, time.Time{}); err != nil || got {
		t.Fatalf("unconfigured retention=(%t, %v), want (false, nil)", got, err)
	}
}
