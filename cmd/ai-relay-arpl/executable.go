package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// currentARPLExecutable resolves the executable that should be placed in
// generated persistence config or used for supervisor children. On Android,
// os.Executable can report the ART linker (/apex/.../linker64) for binaries
// launched through the native/Termux bridge, so the invoked argv[0] is tried
// first and linker paths are rejected.
func currentARPLExecutable() string {
	exe, _ := os.Executable()
	return resolveARPLExecutable(runtime.GOOS, firstArg(), exe)
}

func firstArg() string {
	if len(os.Args) == 0 {
		return ""
	}
	return os.Args[0]
}

func resolveARPLExecutable(goos, argv0, executable string) string {
	if goos == "android" {
		if candidate := usableARPLCandidate(argv0); candidate != "" {
			return candidate
		}
		if candidate := usableARPLCandidate(executable); candidate != "" {
			return candidate
		}
		// Keep generated commands executable when Android hides both paths;
		// the shell/Termux PATH is safer than persisting /apex linker64.
		return "ai-relay-arpl"
	}
	if candidate := usableARPLCandidate(executable); candidate != "" {
		return candidate
	}
	if candidate := usableARPLCandidate(argv0); candidate != "" {
		return candidate
	}
	if strings.TrimSpace(argv0) != "" {
		return argv0
	}
	return "ai-relay-arpl"
}

func usableARPLCandidate(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || androidLinkerPath(candidate) {
		return ""
	}
	if strings.ContainsRune(candidate, filepath.Separator) {
		if abs, err := filepath.Abs(candidate); err == nil {
			candidate = abs
		}
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
		return ""
	}
	if path, err := exec.LookPath(candidate); err == nil && !androidLinkerPath(path) {
		return path
	}
	return ""
}

func androidLinkerPath(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(lower))
	return base == "linker" || strings.HasPrefix(base, "linker") || strings.Contains(lower, "/apex/")
}
