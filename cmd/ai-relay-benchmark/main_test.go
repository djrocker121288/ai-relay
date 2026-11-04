package main

import "testing"

func TestStringListPreservesArgumentBoundaries(t *testing.T) {
	var values stringList
	_ = values.Set("run")
	_ = values.Set("model with spaces")
	if len(values) != 2 || values[1] != "model with spaces" {
		t.Fatalf("values=%q", values)
	}
}
