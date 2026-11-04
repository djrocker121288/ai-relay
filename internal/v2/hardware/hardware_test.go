package hardware

import "testing"

func TestRecommendProfiles(t *testing.T) {
	giB := uint64(1024 * 1024 * 1024)
	tests := []struct {
		name string
		s    Snapshot
		want ProfileName
	}{
		{"light", Snapshot{LogicalCPU: 4, MemoryBytes: 8 * giB}, Light},
		{"standard", Snapshot{LogicalCPU: 8, MemoryBytes: 16 * giB}, Standard},
		{"performance", Snapshot{LogicalCPU: 16, MemoryBytes: 32 * giB}, Performance},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Recommend(test.s)
			if got.Name != test.want {
				t.Fatalf("got %q, want %q", got.Name, test.want)
			}
			if got.MaxCPU+got.ReserveCPU > test.s.LogicalCPU || got.MaxMemoryBytes+got.ReserveMemoryByte > test.s.MemoryBytes {
				t.Fatal("recommended profile exceeds detected capacity")
			}
		})
	}
}

func TestValidateCustomRejectsOvercommit(t *testing.T) {
	giB := uint64(1024 * 1024 * 1024)
	s := Snapshot{LogicalCPU: 8, MemoryBytes: 16 * giB, GPUs: []GPU{{Name: "test", VRAMBytes: 8 * giB}}}
	if err := ValidateCustom(s, Profile{Name: ServerCustom, MaxCPU: 8, ReserveCPU: 1, MaxMemoryBytes: 8 * giB}); err == nil {
		t.Fatal("expected CPU overcommit rejection")
	}
	if err := ValidateCustom(s, Profile{Name: ServerCustom, MaxCPU: 6, ReserveCPU: 2, MaxMemoryBytes: 12 * giB, ReserveMemoryByte: 4 * giB, MaxGPU: 1, MaxVRAMBytes: 8 * giB}); err != nil {
		t.Fatalf("valid custom profile rejected: %v", err)
	}
}

func TestOllamaListParserIsReadOnlyAndDeterministic(t *testing.T) {
	got := parseOllamaList("NAME                 ID              SIZE\nqwen2.5-coder:7b     abc             4 GB\nllama3:8b            def             5 GB\n")
	want := []string{"qwen2.5-coder:7b", "llama3:8b"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestSelectProfileSupportsAllBuiltInsAndCustom(t *testing.T) {
	giB := uint64(1024 * 1024 * 1024)
	s := Snapshot{LogicalCPU: 16, MemoryBytes: 32 * giB, GPUs: []GPU{{Name: "test", VRAMBytes: 8 * giB}}}
	for _, name := range []ProfileName{Light, Standard, Performance} {
		p, err := SelectProfile(s, name, nil)
		if err != nil || p.Name != name {
			t.Fatalf("%s: profile=%+v err=%v", name, p, err)
		}
	}
	if _, err := SelectProfile(s, ServerCustom, nil); err == nil {
		t.Fatal("expected missing custom profile to be rejected")
	}
	custom := Profile{Name: ServerCustom, MaxCPU: 8, ReserveCPU: 2, MaxMemoryBytes: 16 * giB, ReserveMemoryByte: 4 * giB, MaxGPU: 1, MaxVRAMBytes: 8 * giB}
	if got, err := SelectProfile(s, ServerCustom, &custom); err != nil || got != custom {
		t.Fatalf("custom profile=%+v err=%v", got, err)
	}
}
