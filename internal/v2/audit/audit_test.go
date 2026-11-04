package audit

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var validAuditRecord = Record{
	ID:         "event-1",
	OccurredAt: time.Unix(100, 0).UTC(),
	Controller: "controller-1",
	Action:     "tunnel.health",
	Outcome:    "healthy",
	Resource:   "tunnel/resource-1",
}

var validAuditPolicy = Policy{
	Retention:      24 * time.Hour,
	MaxRecordBytes: 1024,
}

func TestRecordValidationRejectsFreeFormUnsafeFields(t *testing.T) {
	if err := validAuditRecord.Validate(); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	for _, mutate := range []func(*Record){
		func(r *Record) { r.ID = "" },
		func(r *Record) { r.OccurredAt = time.Time{} },
		func(r *Record) { r.Controller = "controller\n1" },
		func(r *Record) { r.Action = "action\u200b" },
		func(r *Record) { r.Outcome = strings.Repeat("o", maxOutcomeBytes+1) },
	} {
		candidate := validAuditRecord
		mutate(&candidate)
		if !errors.Is(candidate.Validate(), ErrInvalid) {
			t.Fatalf("record %#v was accepted", candidate)
		}
	}
}

func TestPolicyBoundsRetentionAndSerializedSize(t *testing.T) {
	if err := validAuditPolicy.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	for _, candidate := range []Policy{
		{Retention: 0, MaxRecordBytes: 1024},
		{Retention: 91 * 24 * time.Hour, MaxRecordBytes: 1024},
		{Retention: time.Hour, MaxRecordBytes: minRecordBytes - 1},
		{Retention: time.Hour, MaxRecordBytes: maxRecordBytes + 1},
	} {
		if !errors.Is(candidate.Validate(), ErrInvalid) {
			t.Fatalf("policy %#v was accepted", candidate)
		}
	}
	size, err := validAuditRecord.EncodedSize()
	if err != nil || size <= 0 {
		t.Fatalf("EncodedSize() = %d, %v", size, err)
	}
}

func TestPolicyAcceptsUsesExactRetentionBoundaryAndSizeLimit(t *testing.T) {
	now := validAuditRecord.OccurredAt.Add(24 * time.Hour)
	accepted, err := validAuditPolicy.Accepts(validAuditRecord, now.Add(-time.Nanosecond))
	if err != nil || !accepted {
		t.Fatalf("record before retention boundary accepted=%v err=%v, want true/nil", accepted, err)
	}
	accepted, err = validAuditPolicy.Accepts(validAuditRecord, now)
	if err != nil || accepted {
		t.Fatalf("record at retention boundary accepted=%v err=%v, want false/nil", accepted, err)
	}
	if _, err := validAuditPolicy.Accepts(validAuditRecord, validAuditRecord.OccurredAt.Add(-time.Nanosecond)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("backwards clock error = %v, want ErrInvalid", err)
	}
	tiny := validAuditPolicy
	tiny.MaxRecordBytes = minRecordBytes
	oversized := validAuditRecord
	oversized.Resource = strings.Repeat("r", maxResourceBytes)
	accepted, err = tiny.Accepts(oversized, validAuditRecord.OccurredAt.Add(time.Hour))
	if err != nil || accepted {
		t.Fatalf("oversized record accepted=%v err=%v, want false/nil", accepted, err)
	}
}
