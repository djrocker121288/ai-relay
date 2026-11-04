// Package audit contains the side-effect-free P8 audit-record boundary.
//
// It validates fixed-shape records and evaluates retention without writing,
// deleting, or exposing arbitrary detail. A durable adapter must perform its
// own authenticated ownership, serialization, atomic append, and deletion
// checks before applying these policy results.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxIDBytes       = 128
	maxActionBytes   = 128
	maxOutcomeBytes  = 64
	maxResourceBytes = 512
	minRetention     = time.Hour
	maxRetention     = 90 * 24 * time.Hour
	minRecordBytes   = int64(256)
	maxRecordBytes   = int64(64 << 10)
)

var ErrInvalid = errors.New("invalid audit policy or record")

// ErrWriterBusy reports that another process currently owns the audit writer
// lock. Callers may retry through their own bounded policy.
var ErrWriterBusy = errors.New("audit store writer is busy")

// Record is the intentionally fixed-shape audit vocabulary. It has no free-
// form detail field, token, credential, request body, or error text. Resource
// is an opaque bounded identifier selected by an authenticated adapter; the
// adapter must never place secrets in any identifier field.
type Record struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	Controller string    `json:"controller"`
	Action     string    `json:"action"`
	Outcome    string    `json:"outcome"`
	Resource   string    `json:"resource"`
}

// Policy bounds retention and the serialized record size. A policy is
// required to be explicit so an adapter cannot silently retain records
// forever or accept an unbounded serialized representation.
type Policy struct {
	Retention      time.Duration `json:"retention"`
	MaxRecordBytes int64         `json:"max_record_bytes"`
}

// Validate checks the fixed record vocabulary and timestamp shape. It does
// not decide whether a record is still within retention.
func (r Record) Validate() error {
	if err := validText("record ID", r.ID, maxIDBytes); err != nil {
		return err
	}
	if r.OccurredAt.IsZero() {
		return fmt.Errorf("%w: record time is required", ErrInvalid)
	}
	if err := validText("controller", r.Controller, maxIDBytes); err != nil {
		return err
	}
	if err := validText("action", r.Action, maxActionBytes); err != nil {
		return err
	}
	if err := validText("outcome", r.Outcome, maxOutcomeBytes); err != nil {
		return err
	}
	return validText("resource", r.Resource, maxResourceBytes)
}

// Validate checks that retention and serialized-record limits are bounded.
func (p Policy) Validate() error {
	if p.Retention < minRetention || p.Retention > maxRetention {
		return fmt.Errorf("%w: retention must be between %s and %s", ErrInvalid, minRetention, maxRetention)
	}
	if p.MaxRecordBytes < minRecordBytes || p.MaxRecordBytes > maxRecordBytes {
		return fmt.Errorf("%w: max record bytes must be between %d and %d", ErrInvalid, minRecordBytes, maxRecordBytes)
	}
	return nil
}

// EncodedSize returns the size of the standard JSON representation after
// validating the record. It is an estimate for a future adapter's canonical
// JSON line: JSON whitespace or an envelope added by the adapter is outside
// this boundary and must be included in that adapter's own limit.
func (r Record) EncodedSize() (int64, error) {
	if err := r.Validate(); err != nil {
		return 0, err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return 0, fmt.Errorf("%w: record encoding failed", ErrInvalid)
	}
	return int64(len(encoded)), nil
}

// Accepts reports whether a validated record is within the policy at now.
// The boundary is inclusive: a record exactly at the retention age is due and
// therefore not accepted. It never deletes or persists the record.
func (p Policy) Accepts(r Record, now time.Time) (bool, error) {
	if err := p.Validate(); err != nil {
		return false, err
	}
	if err := r.Validate(); err != nil {
		return false, err
	}
	if now.IsZero() {
		return false, fmt.Errorf("%w: current time is required", ErrInvalid)
	}
	if now.Before(r.OccurredAt) {
		return false, fmt.Errorf("%w: current time precedes record time", ErrInvalid)
	}
	size, err := r.EncodedSize()
	if err != nil {
		return false, err
	}
	if size > p.MaxRecordBytes {
		return false, nil
	}
	return now.Sub(r.OccurredAt) < p.Retention, nil
}

func validText(kind, value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: %s is empty, oversized, malformed, or padded", ErrInvalid, kind)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%w: %s contains a control or format character", ErrInvalid, kind)
		}
	}
	return nil
}
