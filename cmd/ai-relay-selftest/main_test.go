package main

import (
	"strings"
	"testing"

	"github.com/ai-relay/ai-relay/internal/v2/hardware"
)

func TestDecodeCustomProfile(t *testing.T) {
	profile, err := decodeCustomProfile(strings.NewReader(`{"name":"server-custom","max_cpu":4,"max_memory_bytes":4294967296,"reserve_cpu":1,"reserve_memory_bytes":1073741824}`))
	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != hardware.ServerCustom || profile.MaxCPU != 4 {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	if _, err := decodeCustomProfile(strings.NewReader(`{"name":"performance"}`)); err == nil {
		t.Fatal("accepted a non-custom profile")
	}
	if _, err := decodeCustomProfile(strings.NewReader(`{"name":"server-custom","unexpected":true}`)); err == nil {
		t.Fatal("accepted an unknown field")
	}
}
