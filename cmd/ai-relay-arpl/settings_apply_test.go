package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSettingsApplyRendersIdempotentlyWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	s := defaultSettings()
	s.Relay.URL = "wss://example.invalid/arpl"
	s.Relay.TunnelEnabled = false
	s.Security.RelayTokenFile = filepath.Join(dir, "token")
	if err := saveSettings(path, s); err != nil {
		t.Fatal(err)
	}
	if err := applySettings(path, "linux", filepath.Join(dir, "generated"), false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dir, "generated", "ai-relay-arpl-supervisor.service"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(first), "token") || strings.Contains(string(first), "secret") {
		t.Fatalf("service leaked sensitive path: %q", first)
	}
	if err := applySettings(path, "linux", filepath.Join(dir, "generated"), false); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(dir, "generated", "ai-relay-arpl-supervisor.service"))
	if string(first) != string(second) {
		t.Fatal("render is not idempotent")
	}
	cron, err := os.ReadFile(filepath.Join(dir, "generated", "arpl-supervisor.cron"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cron), "# ai-relay-arpl-supervisor") || strings.Count(string(cron), "# ai-relay-arpl-supervisor") != 1 {
		t.Fatalf("fallback cron entry missing or duplicated: %q", cron)
	}
	if strings.Contains(string(cron), "token") || strings.Contains(string(cron), "secret") {
		t.Fatalf("cron leaked sensitive path: %q", cron)
	}
	if _, err := renderServices(s, path, "windows"); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorMultiPeerPlansExactlyOneChildPerRole(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	s := defaultSettings()
	s.Relay.URL = "wss://example.invalid/arpl"
	s.Relay.TunnelEnabled = false
	key1 := strings.Repeat("11", 32)
	key2 := strings.Repeat("22", 32)
	key3 := strings.Repeat("33", 32)
	s.Peers = []PeerSettings{
		{Name: "one", Enabled: true, PublicKey: key1, InboundPair: strings.Repeat("a", 64), OutboundPair: strings.Repeat("b", 64)},
		{Name: "two", Enabled: true, PublicKey: key2, InboundPair: strings.Repeat("c", 64), OutboundPair: strings.Repeat("d", 64)},
		{Name: "disabled", Enabled: false, PublicKey: key3, InboundPair: strings.Repeat("e", 64), OutboundPair: strings.Repeat("f", 64)},
	}
	if err := validateSettings(s); err != nil {
		t.Fatal(err)
	}
	plans := supervisionPlans(s, settingsPath, "/tmp/ai-relay-arpl")
	if len(plans) != 4 {
		t.Fatalf("plans=%d, want exactly two host and two client children: %#v", len(plans), plans)
	}
	seen := map[string]int{}
	for _, plan := range plans {
		seen[plan.Role]++
		if !containsArgs(plan.Args, "--peer-key") || !containsArgs(plan.Args, "--relay-pair") || !containsArgs(plan.Args, "--settings-file") {
			t.Fatalf("child does not have explicit peer/settings flags: %#v", plan.Args)
		}
		if strings.Contains(strings.Join(plan.Args, " "), "client connect --settings-file") && !containsArgs(plan.Args, "--control-state") {
			t.Fatalf("client plan lacks explicit control state: %#v", plan.Args)
		}
	}
	if seen["host"] != 2 || seen["client"] != 2 {
		t.Fatalf("role counts=%v, want host=2 client=2", seen)
	}
	marker := peerStopMarker(settingsPath, s.Peers[0])
	if err := writePeerStopMarker(marker); err != nil {
		t.Fatal(err)
	}
	plans = supervisionPlans(s, settingsPath, "/tmp/ai-relay-arpl")
	if len(plans) != 3 {
		t.Fatalf("intentional stop did not suppress exactly one client: %#v", plans)
	}
	if err := clearPeerStopMarker(marker); err != nil {
		t.Fatal(err)
	}
}

func containsArgs(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func TestSupervisorStaleLockRecoveryAndLiveLockProtection(t *testing.T) {
	dir := t.TempDir()
	lockDir := filepath.Join(dir, supervisorLockName)
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lockDir, supervisorPIDName), []byte("2147483647\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireSupervisorLock(dir)
	if err != nil {
		t.Fatalf("stale lock was not recovered: %v", err)
	}
	if err := acquireLiveLockCheck(dir); err != nil {
		t.Fatal(err)
	}
	lock.Release()
}

func acquireLiveLockCheck(dir string) error {
	_, err := acquireSupervisorLock(dir)
	if !errors.Is(err, errSupervisorAlreadyRunning) {
		return fmt.Errorf("live lock result=%v, want already-running error", err)
	}
	return nil
}

func TestSupervisorFallbackRenderingHasNoRealCrontabSideEffect(t *testing.T) {
	entry := cronEntry("/opt/ai-relay-arpl", "/tmp/arpl/settings.json")
	if !strings.Contains(entry, "*/1 * * * *") || !strings.Contains(entry, "supervisor run") || !strings.Contains(entry, "# ai-relay-arpl-supervisor") {
		t.Fatalf("unexpected cron entry: %q", entry)
	}
	if strings.Count(entry, "# ai-relay-arpl-supervisor") != 1 {
		t.Fatalf("cron marker count=%d", strings.Count(entry, "# ai-relay-arpl-supervisor"))
	}
}

func TestSupervisorBackoffBounds(t *testing.T) {
	got := minChildBackoff
	for i := 0; i < 10; i++ {
		got = nextChildBackoff(got)
	}
	if got != maxChildBackoff {
		t.Fatalf("backoff=%s, want cap %s", got, maxChildBackoff)
	}
	if nextChildBackoff(maxChildBackoff) != maxChildBackoff {
		t.Fatal("backoff exceeded maximum")
	}
	if minChildBackoff < time.Second || maxChildBackoff > 60*time.Second {
		t.Fatalf("backoff bounds are outside release limits: %s..%s", minChildBackoff, maxChildBackoff)
	}
}
