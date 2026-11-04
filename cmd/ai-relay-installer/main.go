// Command ai-relay-installer is the cross-platform public entry point for the
// AI Relay + ARPL all-in-one installer. The platform scripts remain the source
// of installation truth; this command only locates and invokes them safely.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var version = "dev"

type options struct {
	action            string
	sourceDir         string
	baseURL           string
	version           string
	role              string
	prefix            string
	configDir         string
	stateDir          string
	gateway           string
	credentialFile    string
	enrollTokenFile   string
	enrollmentPayload string
	peerName          string
	activate          bool
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai-relay-installer:", err)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := rejectSecretEnvironment(); err != nil {
		fmt.Fprintln(os.Stderr, "ai-relay-installer:", err)
		os.Exit(2)
	}

	if opts.version == "" || opts.version == "dev" {
		if envVersion := strings.TrimSpace(os.Getenv("AI_RELAY_VERSION")); envVersion != "" {
			opts.version = envVersion
		}
	}
	if opts.version == "" || opts.version == "dev" {
		opts.version = "2.1.0"
	}

	script, err := findInstallerScript()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai-relay-installer:", err)
		os.Exit(1)
	}

	cmd, err := interpreter(script)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai-relay-installer:", err)
		os.Exit(1)
	}
	cmd.Args = append(cmd.Args, scriptArguments(opts)...)
	cmd.Env = append(os.Environ(), "AI_RELAY_INSTALLER_BOOTSTRAP=1", "AI_RELAY_VERSION="+opts.version)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			fmt.Fprintf(os.Stderr, "AI Relay + ARPL installer failed (exit %d).\n", exitErr.ExitCode())
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "AI Relay + ARPL installer failed:", err)
		os.Exit(1)
	}
	fmt.Println("AI Relay + ARPL installer completed; review the status above for enrollment and activation state.")
}

func parseOptions(args []string) (options, error) {
	opts := options{action: "install", role: "endpoint", version: version}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "install" || arg == "status" || arg == "doctor" || arg == "repair" {
			if opts.action != "install" {
				return options{}, fmt.Errorf("more than one action supplied")
			}
			opts.action = arg
			continue
		}
		if arg == "--help" || arg == "-h" {
			fmt.Print(usage)
			os.Exit(0)
		}
		if arg == "--activate" {
			opts.activate = true
			continue
		}
		name, value, ok := splitOption(arg)
		if !ok {
			return options{}, fmt.Errorf("unknown argument %q", arg)
		}
		if name == "--status" || name == "--doctor" || name == "--repair" {
			if value != "" {
				return options{}, fmt.Errorf("%s does not take a value", name)
			}
			if opts.action != "install" {
				return options{}, fmt.Errorf("more than one action supplied")
			}
			opts.action = strings.TrimPrefix(name, "--")
			continue
		}
		if strings.HasPrefix(arg, "--enroll-token=") || strings.HasPrefix(arg, "--token=") || strings.HasPrefix(arg, "--credential=") {
			return options{}, fmt.Errorf("secret values are never accepted on the command line; use a protected file option")
		}
		if value == "" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return options{}, fmt.Errorf("%s requires a value", name)
			}
			i++
			value = args[i]
		}
		switch name {
		case "--source-dir":
			opts.sourceDir = value
		case "--base-url":
			opts.baseURL = value
		case "--version":
			opts.version = value
		case "--role":
			if value != "endpoint" && value != "full" && value != "server" {
				return options{}, fmt.Errorf("role must be endpoint, full, or server")
			}
			opts.role = value
		case "--prefix":
			opts.prefix = value
		case "--config-dir":
			opts.configDir = value
		case "--state-dir":
			opts.stateDir = value
		case "--gateway":
			opts.gateway = value
		case "--credential-file":
			opts.credentialFile = value
		case "--enroll-token-file":
			opts.enrollTokenFile = value
		case "--enrollment-payload-file":
			opts.enrollmentPayload = value
		case "--peer-name":
			opts.peerName = value
		default:
			return options{}, fmt.Errorf("unknown argument %q", arg)
		}
	}
	return opts, nil
}

func splitOption(arg string) (string, string, bool) {
	if !strings.HasPrefix(arg, "--") {
		return "", "", false
	}
	parts := strings.SplitN(arg, "=", 2)
	if len(parts) == 2 {
		return parts[0], parts[1], true
	}
	return arg, "", true
}

func scriptArguments(opts options) []string {
	if runtime.GOOS == "windows" {
		args := make([]string, 0, 24)
		if opts.sourceDir != "" {
			args = append(args, "-SourceDir", opts.sourceDir)
		}
		if opts.baseURL != "" {
			args = append(args, "-BaseUrl", opts.baseURL)
		}
		args = append(args, "-Version", opts.version, "-Role", opts.role)
		for _, pair := range [][2]string{{"-Prefix", opts.prefix}, {"-ConfigDir", opts.configDir}, {"-StateDir", opts.stateDir}, {"-Gateway", opts.gateway}, {"-CredentialFile", opts.credentialFile}, {"-EnrollTokenFile", opts.enrollTokenFile}, {"-EnrollmentPayloadFile", opts.enrollmentPayload}, {"-PeerName", opts.peerName}} {
			if pair[1] != "" {
				args = append(args, pair[0], pair[1])
			}
		}
		if opts.activate {
			args = append(args, "-Activate")
		}
		switch opts.action {
		case "status":
			args = append(args, "-Status")
		case "doctor":
			args = append(args, "-Doctor")
		case "repair":
			args = append(args, "-Repair")
		}
		return args
	}

	args := make([]string, 0, 24)
	if opts.sourceDir != "" {
		args = append(args, "--source-dir", opts.sourceDir)
	}
	if opts.baseURL != "" {
		args = append(args, "--base-url", opts.baseURL)
	}
	args = append(args, "--version", opts.version, "--role", opts.role)
	for _, pair := range [][2]string{{"--prefix", opts.prefix}, {"--config-dir", opts.configDir}, {"--state-dir", opts.stateDir}, {"--gateway", opts.gateway}, {"--credential-file", opts.credentialFile}, {"--enroll-token-file", opts.enrollTokenFile}, {"--enrollment-payload-file", opts.enrollmentPayload}, {"--peer-name", opts.peerName}} {
		if pair[1] != "" {
			args = append(args, pair[0], pair[1])
		}
	}
	if opts.activate {
		args = append(args, "--activate")
	}
	if opts.action != "install" {
		args = append(args, "--"+opts.action)
	}
	return args
}

func findInstallerScript() (string, error) {
	name := "install-unix.sh"
	if runtime.GOOS == "windows" {
		name = "install-windows.ps1"
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot locate bootstrap executable: %w", err)
	}
	exeDir := filepath.Dir(exe)
	workingDir, _ := os.Getwd()
	candidates := []string{
		os.Getenv("AI_RELAY_INSTALLER_SCRIPT"),
		filepath.Join(exeDir, name),
		filepath.Join(exeDir, "release", name),
		filepath.Join(exeDir, "Resources", name),
		filepath.Join(exeDir, "..", "Resources", name),
		filepath.Join(workingDir, name),
		filepath.Join(workingDir, "packaging", "all-in-one", name),
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		candidate, err = filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		info, statErr := os.Lstat(candidate)
		if statErr == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s not found beside the bootstrap, in its Resources directory, or in packaging/all-in-one", name)
}

func interpreter(script string) (*exec.Cmd, error) {
	if runtime.GOOS == "windows" {
		for _, candidate := range []string{"powershell.exe", "pwsh.exe", "pwsh"} {
			if path, err := exec.LookPath(candidate); err == nil {
				return exec.Command(path, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script), nil
			}
		}
		return nil, fmt.Errorf("Windows PowerShell was not found; the setup executable does not install or bypass PowerShell")
	}
	return exec.Command("/bin/sh", script), nil
}

func rejectSecretEnvironment() error {
	for _, name := range []string{"AI_RELAY_ENROLL_TOKEN", "AI_RELAY_TOKEN", "ARPL_ENROLLMENT_TOKEN"} {
		if os.Getenv(name) != "" {
			return fmt.Errorf("%s is not accepted; place the one-use credential in a protected file and use --enroll-token-file", name)
		}
	}
	return nil
}

const usage = `Usage: ai-relay-installer [install|status|doctor|repair] [options]

The bootstrap invokes the existing staging-first AI Relay + ARPL installer.
Enrollment is never implicit: pass an existing protected credential file or
an explicit protected one-use token file when enrollment is intended.

Options:
  --role endpoint|full|server
  --source-dir DIR       local release directory
  --base-url URL         release URL
  --version VERSION
  --prefix DIR --config-dir DIR --state-dir DIR
  --gateway URL
  --credential-file FILE
  --enroll-token-file FILE
  --enrollment-payload-file FILE --peer-name NAME
  --activate             explicitly request native persistence activation
  --help

Token and credential contents are never accepted as command-line arguments.
`
