package confidence

import (
	"math"
	"strings"
	"testing"
	"time"
)

func request(score float64) Request {
	policy := DefaultPolicy()
	policy.AllowedTargets = []string{"human", "controller"}
	policy.AuthorizedScopes = []string{"read-repo"}
	return Request{DecisionID: "d-1", TaskID: "t-1", OwnerID: "controller-1", Now: time.Unix(123, 0).UTC(), Policy: policy, Evidence: []Evidence{
		{Name: "deterministic-validation", Score: score, Weight: 0.5, Method: "test-suite/v1"},
		{Name: "runtime-model", Score: score, Weight: 0.3, Method: "benchmark/v1"},
		{Name: "task-risk", Score: score, Weight: 0.2, Method: "risk-policy/v1"},
	}}
}

func TestEvaluateOutcomesAndReplayVerification(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		want  Outcome
	}{
		{"automatic", 0.9, OutcomeAuto},
		{"escalation", 0.65, OutcomeEscalate},
		{"rejected", 0.2, OutcomeReject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := request(tt.score)
			if tt.want == OutcomeEscalate {
				req.EscalationTarget = "human"
				req.RequestedScopes = []string{"read-repo"}
			}
			decision, err := Evaluate(req)
			if err != nil || decision.Outcome != tt.want {
				t.Fatalf("evaluate = %#v, %v; want %s", decision, err, tt.want)
			}
			if err := Verify(decision); err != nil {
				t.Fatalf("verify: %v", err)
			}
			decision.Reason = "tampered"
			if Verify(decision) == nil {
				t.Fatal("tampered decision verified")
			}
		})
	}
}

func TestInvalidEvidenceAndPrivilegeExpansionAreRejected(t *testing.T) {
	bad := request(0.8)
	bad.Evidence[0].Score = 1.1
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("out-of-range evidence accepted")
	}
	bad = request(0.6)
	bad.EscalationTarget = "human"
	bad.RequestedScopes = []string{"write-repo"}
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("unauthorized escalation scope accepted")
	}
	bad = request(0.6)
	bad.EscalationTarget = "unknown"
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("unknown escalation target accepted")
	}
	if _, err := Evaluate(request(0.6)); err == nil {
		t.Fatal("in-band confidence without an escalation target accepted")
	}
}

func TestEvidenceOrderDoesNotChangeDigest(t *testing.T) {
	first := request(0.9)
	second := request(0.9)
	second.Evidence[0], second.Evidence[1] = second.Evidence[1], second.Evidence[0]
	a, err := Evaluate(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Evaluate(second)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatalf("digest changed with evidence order: %s != %s", a.Digest, b.Digest)
	}
}

func TestPolicyIsPartOfReplayAndSemanticTamperingFails(t *testing.T) {
	decision, err := Evaluate(request(0.9))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Policy.ID != "ai-relay-confidence/v1" {
		t.Fatalf("policy was not retained: %#v", decision.Policy)
	}
	decision.Policy.AutoThreshold = 0.95
	decision.Digest, err = digest(decision)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(decision) == nil {
		t.Fatal("semantically inconsistent decision verified after digest recomputation")
	}
}

func TestOwnerIsRequiredAndCoveredByReplay(t *testing.T) {
	bad := request(0.9)
	bad.OwnerID = ""
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("missing owner accepted")
	}
	decision, err := Evaluate(request(0.9))
	if err != nil {
		t.Fatal(err)
	}
	decision.OwnerID = "controller-2"
	if Verify(decision) == nil {
		t.Fatal("tampered owner verified")
	}
}

func TestRequiredEvidenceFiniteNumbersAndBounds(t *testing.T) {
	bad := request(0.9)
	bad.Evidence = bad.Evidence[:2]
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("missing task-risk evidence accepted")
	}
	bad = request(0.9)
	bad.Evidence[0].Score = math.NaN()
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("NaN score accepted")
	}
	bad = request(0.9)
	bad.Evidence[1].Name = bad.Evidence[0].Name
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("duplicate evidence name accepted")
	}
	bad = request(0.9)
	bad.Evidence[0].Detail = strings.Repeat("x", maxDetailLength+1)
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("oversized evidence detail accepted")
	}
	bad = request(0.9)
	bad.Policy.AutoThreshold = math.NaN()
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("NaN threshold accepted")
	}
}

func TestEscalationMetadataOnlyAllowedForEscalation(t *testing.T) {
	bad := request(0.9)
	bad.EscalationTarget = "human"
	bad.RequestedScopes = []string{"read-repo"}
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("automatic decision accepted escalation metadata")
	}
	bad = request(0.2)
	bad.EscalationTarget = "human"
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("rejected decision accepted escalation metadata")
	}
}
