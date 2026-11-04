package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ai-relay/ai-relay/internal/audit"
	"github.com/ai-relay/ai-relay/internal/protocol"
	"github.com/ai-relay/ai-relay/internal/v2/confidence"
)

// evaluateConfidence is an MCP adapter around the side-effect-free policy
// core. The gateway owns the allow-list; callers cannot submit a weaker policy
// or turn an escalation into execution.
func (s *Server) evaluateConfidence(call map[string]any, controller *ControllerRecord) (any, *protocol.Error) {
	a, ok := call["arguments"].(map[string]any)
	if !ok {
		return nil, &protocol.Error{Code: "INVALID_ARGUMENT", Message: "arguments"}
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, &protocol.Error{Code: "INVALID_ARGUMENT", Message: "invalid confidence arguments"}
	}
	var input struct {
		DecisionID       string                `json:"decision_id"`
		TaskID           string                `json:"task_id"`
		Evidence         []confidence.Evidence `json:"evidence"`
		EscalationTarget string                `json:"escalation_target,omitempty"`
		RequestedScopes  []string              `json:"requested_scopes,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, &protocol.Error{Code: "INVALID_ARGUMENT", Message: "invalid confidence arguments"}
	}
	policy := confidence.DefaultPolicy()
	policy.AllowedTargets = []string{"human", "controller"}
	// These are action descriptions, not gateway/controller permissions. The
	// policy core requires them to be pre-authorized and never applies them.
	policy.AuthorizedScopes = []string{"read-repo"}
	for _, scope := range controller.Scopes {
		if scope == scopeRead || scope == scopeSubmit {
			policy.AuthorizedScopes = append(policy.AuthorizedScopes, scope)
		}
	}
	decision, err := confidence.Evaluate(confidence.Request{
		DecisionID: input.DecisionID, TaskID: input.TaskID, OwnerID: controller.ID, Evidence: input.Evidence,
		EscalationTarget: input.EscalationTarget, RequestedScopes: input.RequestedScopes,
		Policy: policy, Now: time.Now().UTC(),
	})
	if err != nil {
		return nil, &protocol.Error{Code: "INVALID_ARGUMENT", Message: err.Error()}
	}
	if err := confidence.Verify(decision); err != nil {
		return nil, &protocol.Error{Code: "INTERNAL", Message: "confidence replay verification failed"}
	}
	if err := s.audit.Write(audit.Event{Action: "confidence.decision", Detail: map[string]any{
		"decision_id": decision.DecisionID, "task_id": decision.TaskID, "outcome": decision.Outcome,
		"target": decision.Target, "scopes": decision.Scopes, "digest": decision.Digest,
		"controller": controller.ID,
	}}); err != nil {
		return nil, &protocol.Error{Code: "INTERNAL", Message: fmt.Sprintf("confidence audit failed: %v", err)}
	}
	return decision, nil
}
