package main

import (
	"os"
	"strings"
	"testing"
)

func TestParseOptionsUsesFileOnlyEnrollment(t *testing.T) {
	opts, err := parseOptions([]string{"install", "--role", "server", "--enroll-token-file", "/tmp/enroll.token", "--gateway", "https://relay.example"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.role != "server" || opts.enrollTokenFile != "/tmp/enroll.token" || opts.gateway == "" {
		t.Fatalf("parsed options = %#v", opts)
	}
	if _, err := parseOptions([]string{"--enroll-token=secret-value"}); err == nil {
		t.Fatal("inline enrollment token was accepted")
	}
}

func TestScriptArgumentsDoNotContainSecretContents(t *testing.T) {
	opts := options{version: "2.1.0", role: "endpoint", enrollTokenFile: "/private/token-file"}
	joined := strings.Join(scriptArguments(opts), " ")
	if strings.Contains(joined, "secret") || !strings.Contains(joined, "/private/token-file") {
		t.Fatalf("unexpected script arguments: %q", joined)
	}
}

func TestRejectSecretEnvironment(t *testing.T) {
	const name = "AI_RELAY_ENROLL_TOKEN"
	old, had := os.LookupEnv(name)
	if err := os.Setenv(name, "do-not-use"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(name, old)
		} else {
			_ = os.Unsetenv(name)
		}
	})
	if err := rejectSecretEnvironment(); err == nil {
		t.Fatal("secret environment variable was accepted")
	}
}
