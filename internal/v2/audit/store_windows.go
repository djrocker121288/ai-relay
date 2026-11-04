//go:build windows

package audit

import (
	"os"
	"path/filepath"
)

func ensurePrivateAuditParent(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0700)
}

func openAuditRead(path string) (*os.File, error) { return os.Open(path) }

func replaceAuditFile(from, to string) error { return os.Rename(from, to) }

func syncAuditDirectory(string) error { return nil }
