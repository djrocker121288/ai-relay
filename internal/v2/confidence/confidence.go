// Package confidence evaluates bounded evidence and decides whether work may
// continue or must be escalated. It does not grant privileges or perform the
// escalation itself.
package confidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

type Outcome string

const (
	OutcomeAuto     Outcome = "auto"
	OutcomeEscalate Outcome = "escalate"
	OutcomeReject   Outcome = "reject"
)

type Evidence struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
	Method string  `json:"method"`
	Detail string  `json:"detail,omitempty"`
}

type Policy struct {
	ID                string   `json:"id"`
	AutoThreshold     float64  `json:"auto_threshold"`
	EscalateThreshold float64  `json:"escalate_threshold"`
	MaxEvidence       int      `json:"max_evidence"`
	RequiredEvidence  []string `json:"required_evidence"`
	AllowedTargets    []string `json:"allowed_targets,omitempty"`
	AuthorizedScopes  []string `json:"authorized_scopes,omitempty"`
}

type Request struct {
	DecisionID       string     `json:"decision_id"`
	TaskID           string     `json:"task_id"`
	OwnerID          string     `json:"owner_id"`
	Evidence         []Evidence `json:"evidence"`
	EscalationTarget string     `json:"escalation_target,omitempty"`
	RequestedScopes  []string   `json:"requested_scopes,omitempty"`
	Policy           Policy     `json:"policy"`
	Now              time.Time  `json:"now"`
}

type Decision struct {
	DecisionID string     `json:"decision_id"`
	TaskID     string     `json:"task_id"`
	OwnerID    string     `json:"owner_id"`
	Score      float64    `json:"score"`
	Outcome    Outcome    `json:"outcome"`
	Reason     string     `json:"reason"`
	Evidence   []Evidence `json:"evidence"`
	Policy     Policy     `json:"policy"`
	Target     string     `json:"escalation_target,omitempty"`
	Scopes     []string   `json:"requested_scopes,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	Digest     string     `json:"digest"`
}

var ErrInvalid = errors.New("invalid confidence request")

const (
	maxIDLength     = 128
	maxNameLength   = 64
	maxMethodLength = 128
	maxDetailLength = 1024
	maxListItems    = 32
)

func DefaultPolicy() Policy {
	return Policy{ID: "ai-relay-confidence/v1", AutoThreshold: 0.80, EscalateThreshold: 0.50, MaxEvidence: 8, RequiredEvidence: []string{"deterministic-validation", "runtime-model", "task-risk"}}
}

func Evaluate(req Request) (Decision, error) {
	if err := validate(req); err != nil {
		return Decision{}, err
	}
	evidence := append([]Evidence(nil), req.Evidence...)
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Name < evidence[j].Name })
	score, totalWeight := 0.0, 0.0
	for _, item := range evidence {
		score += item.Score * item.Weight
		totalWeight += item.Weight
	}
	score /= totalWeight
	if score >= req.Policy.EscalateThreshold && score < req.Policy.AutoThreshold && strings.TrimSpace(req.EscalationTarget) == "" {
		return Decision{}, fmt.Errorf("%w: escalation target is required for in-band confidence", ErrInvalid)
	}
	if (score >= req.Policy.AutoThreshold || score < req.Policy.EscalateThreshold) && (req.EscalationTarget != "" || len(req.RequestedScopes) > 0) {
		return Decision{}, fmt.Errorf("%w: escalation metadata is valid only for an escalation outcome", ErrInvalid)
	}
	decision := Decision{DecisionID: req.DecisionID, TaskID: req.TaskID, OwnerID: req.OwnerID, Score: score, Evidence: evidence, Policy: clonePolicy(req.Policy), CreatedAt: req.Now.UTC()}
	if score >= req.Policy.AutoThreshold {
		decision.Outcome, decision.Reason = OutcomeAuto, "confidence meets automatic-execution threshold"
	} else if score >= req.Policy.EscalateThreshold {
		decision.Outcome, decision.Reason = OutcomeEscalate, "confidence requires an authorized escalation target"
		decision.Target, decision.Scopes = req.EscalationTarget, append([]string(nil), req.RequestedScopes...)
	} else {
		decision.Outcome, decision.Reason = OutcomeReject, "confidence is below the escalation threshold"
	}
	digest, err := digest(decision)
	if err != nil {
		return Decision{}, err
	}
	decision.Digest = digest
	return decision, nil
}

func Verify(decision Decision) error {
	if decision.Digest == "" {
		return ErrInvalid
	}
	want, err := digest(decision)
	if err != nil {
		return err
	}
	if want != decision.Digest {
		return fmt.Errorf("decision digest mismatch")
	}
	replayed, err := Evaluate(Request{DecisionID: decision.DecisionID, TaskID: decision.TaskID, OwnerID: decision.OwnerID, Evidence: decision.Evidence, EscalationTarget: decision.Target, RequestedScopes: decision.Scopes, Policy: decision.Policy, Now: decision.CreatedAt})
	if err != nil {
		return fmt.Errorf("decision replay failed: %w", err)
	}
	if replayed.Digest != decision.Digest {
		return fmt.Errorf("decision does not match replayed policy outcome")
	}
	return nil
}

func validate(req Request) error {
	if !boundedText(req.DecisionID, maxIDLength) || !boundedText(req.TaskID, maxIDLength) || !boundedText(req.OwnerID, maxIDLength) || req.Now.IsZero() {
		return fmt.Errorf("%w: decision ID, task ID, owner ID, and timestamp are required", ErrInvalid)
	}
	p := req.Policy
	if !boundedText(p.ID, maxIDLength) || p.MaxEvidence <= 0 || p.MaxEvidence > maxListItems || len(req.Evidence) == 0 || len(req.Evidence) > p.MaxEvidence || !finiteUnit(p.EscalateThreshold) || !finiteUnit(p.AutoThreshold) || p.EscalateThreshold > p.AutoThreshold {
		return fmt.Errorf("%w: invalid policy or evidence count", ErrInvalid)
	}
	if len(p.RequiredEvidence) == 0 || len(p.RequiredEvidence) > p.MaxEvidence || len(p.AllowedTargets) > maxListItems || len(p.AuthorizedScopes) > maxListItems || len(req.RequestedScopes) > maxListItems {
		return fmt.Errorf("%w: policy list is empty or exceeds its bound", ErrInvalid)
	}
	if !validList(p.RequiredEvidence, maxNameLength) || !validList(p.AllowedTargets, maxIDLength) || !validList(p.AuthorizedScopes, maxIDLength) || !validList(req.RequestedScopes, maxIDLength) || (req.EscalationTarget != "" && !boundedText(req.EscalationTarget, maxIDLength)) {
		return fmt.Errorf("%w: policy or escalation list contains an invalid value", ErrInvalid)
	}
	allowedTargets := set(p.AllowedTargets)
	authorizedScopes := set(p.AuthorizedScopes)
	required := set(p.RequiredEvidence)
	weight := 0.0
	seen := make(map[string]bool, len(req.Evidence))
	for _, item := range req.Evidence {
		if !boundedText(item.Name, maxNameLength) || !boundedText(item.Method, maxMethodLength) || len(item.Detail) > maxDetailLength || !finiteUnit(item.Score) || math.IsNaN(item.Weight) || math.IsInf(item.Weight, 0) || item.Weight <= 0 || seen[item.Name] {
			return fmt.Errorf("%w: evidence must have bounded score and positive weight", ErrInvalid)
		}
		seen[item.Name] = true
		weight += item.Weight
	}
	if weight < 0.999999 || weight > 1.000001 {
		return fmt.Errorf("%w: evidence weights must sum to one", ErrInvalid)
	}
	for name := range required {
		if !seen[name] {
			return fmt.Errorf("%w: required evidence %q is missing", ErrInvalid, name)
		}
	}
	if req.EscalationTarget != "" && !allowedTargets[req.EscalationTarget] {
		return fmt.Errorf("%w: escalation target is not authorized", ErrInvalid)
	}
	for _, scope := range req.RequestedScopes {
		if !authorizedScopes[scope] {
			return fmt.Errorf("%w: requested scope is not authorized", ErrInvalid)
		}
	}
	if req.EscalationTarget == "" && len(req.RequestedScopes) > 0 {
		return fmt.Errorf("%w: scopes require an escalation target", ErrInvalid)
	}
	return nil
}

func finiteUnit(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}

func boundedText(value string, limit int) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}

func clonePolicy(policy Policy) Policy {
	copy := policy
	copy.RequiredEvidence = append([]string(nil), policy.RequiredEvidence...)
	copy.AllowedTargets = append([]string(nil), policy.AllowedTargets...)
	copy.AuthorizedScopes = append([]string(nil), policy.AuthorizedScopes...)
	return copy
}

func validList(values []string, limit int) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !boundedText(value, limit) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func set(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func digest(decision Decision) (string, error) {
	copy := decision
	copy.Digest = ""
	copy.Evidence = append([]Evidence(nil), decision.Evidence...)
	sort.Slice(copy.Evidence, func(i, j int) bool { return copy.Evidence[i].Name < copy.Evidence[j].Name })
	raw, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
