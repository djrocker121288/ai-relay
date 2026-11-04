//go:build !linux && !darwin && !windows

package main

import "os"

// Unsupported platforms retain the existing identity-checked open. They do
// not claim the no-follow primitive provided by the native targets above.
func openEvidenceNoFollow(path string) (*os.File, error) { return os.Open(path) }
