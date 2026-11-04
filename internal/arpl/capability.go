package arpl

import (
	"errors"
	"sort"
	"strings"
)

const (
	CapabilityControl    = "control/status"
	CapabilityExec       = "exec"
	CapabilityTerminal   = "terminal"
	CapabilityFileRead   = "file/read"
	CapabilityFileWrite  = "file/write"
	CapabilitySync       = "sync"
	CapabilityJob        = "job"
	CapabilityService    = "service-control"
	CapabilityEnrollment = "enrollment/admin"
	CapabilityUpdate     = "update"
	CapabilityAudit      = "audit"
)

var allCapabilities = []string{CapabilityControl, CapabilityExec, CapabilityTerminal, CapabilityFileRead, CapabilityFileWrite, CapabilitySync, CapabilityJob, CapabilityService, CapabilityEnrollment, CapabilityUpdate, CapabilityAudit}

func AllCapabilities() []string { return append([]string(nil), allCapabilities...) }

func NormalizeCapabilities(in []string) []string {
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			seen[v] = true
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func HasCapability(caps []string, required string) bool {
	if required == "" || len(caps) == 0 {
		return required == ""
	}
	for _, c := range caps {
		if c == required || c == "*" {
			return true
		}
	}
	return false
}

var ErrCapabilityDenied = errors.New("ARPL capability denied")

func authorizeCapabilities(caps []string, required string) error {
	if required == "" || len(caps) == 0 {
		return nil
	} // legacy trusted peers
	if !HasCapability(caps, required) {
		return ErrCapabilityDenied
	}
	return nil
}
