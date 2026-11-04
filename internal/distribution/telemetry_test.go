package distribution

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTelemetryOptOutSendsNothing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "telemetry.json")
	c, err := LoadTelemetry(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled {
		t.Fatal("new telemetry was enabled")
	}
	if err := SaveTelemetry(p, c); err != nil {
		t.Fatal(err)
	}
	if err := SendTelemetry(nil, "https://example.invalid", p, nil); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("unexpected: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}
