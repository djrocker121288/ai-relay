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

type renderedService struct {
	Name, Content string
	Mode          os.FileMode
}

var legacyLinuxServiceNames = []string{
	"ai-relay-arpl-host.service",
	"ai-relay-arpl-client.service",
}

func renderServices(s ARPLSettings, settingsPath, platform string) ([]renderedService, error) {
	if err := validateSettings(s); err != nil {
		return nil, err
	}
	if platform == "" {
		platform = runtime.GOOS
	}
	exe := currentARPLExecutable()
	units := []renderedService{}
	switch platform {
	case "linux":
		if s.Service.StartHost || s.Service.StartClient {
			units = append(units,
				renderedService{"arpl-user-supervisor.sh", userSupervisorScript(exe, settingsPath), 0700},
				renderedService{"ai-relay-arpl-supervisor.service", supervisorUnit(exe, settingsPath), 0644},
				renderedService{"arpl-supervisor-cron.sh", userSupervisorScript(exe, settingsPath), 0700},
				renderedService{"arpl-supervisor.cron", supervisorCronFile(exe, settingsPath), 0600},
			)
		}
	case "darwin":
		if s.Service.StartClient {
			units = append(units, renderedService{"com.ai-relay.arpl.plist", launchdPlist(exe, settingsPath, []string{"client", "connect"}, "com.ai-relay.arpl"), 0600})
		}
		if s.Service.StartHost {
			units = append(units, renderedService{"com.ai-relay.arpl-host.plist", launchdPlist(exe, settingsPath, []string{"host", "run"}, "com.ai-relay.arpl-host"), 0600})
		}
	case "windows":
		if s.Service.StartClient {
			units = append(units, renderedService{"arpl-register-client-task.ps1", windowsTaskScript(exe, settingsPath, "client connect"), 0600})
		}
		if s.Service.StartHost {
			units = append(units, renderedService{"arpl-register-host-task.ps1", windowsTaskScript(exe, settingsPath, "host run"), 0600})
		}
	case "android":
		units = append(units, renderedService{"arpl-termux-start.sh", termuxScript(exe, settingsPath, s), 0700})
	default:
		return nil, errors.New("unsupported service rendering platform: " + platform)
	}
	return units, nil
}

func userSupervisorScript(exe, settings string) string {
	return fmt.Sprintf("#!/bin/sh\nset -eu\nexec %s supervisor run --settings-file %s\n", shellQuote(exe), shellQuote(settings))
}

func supervisorUnit(exe, settings string) string {
	return fmt.Sprintf("[Unit]\nDescription=AI Relay ARPL supervisor\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart=%s supervisor run --settings-file %s\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n", quoteUnit(exe), quoteUnit(settings))
}

func supervisorCronFile(exe, settings string) string {
	return cronEntry(exe, settings) + "\n"
}

func cronEntry(exe, settings string) string {
	return "*/1 * * * * " + shellQuote(exe) + " supervisor run --settings-file " + shellQuote(settings) + " # ai-relay-arpl-supervisor"
}

func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
func quoteUnit(v string) string {
	return strings.NewReplacer("\\", "\\\\", " ", "\\ ", "\t", "\\t", "\"", "\\\"", "'", "\\'", "$", "\\$", "%", "\\%").Replace(v)
}
func xmlEscape(v string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;").Replace(v)
}
func launchdPlist(exe, path string, args []string, label string) string {
	parts := []string{exe}
	parts = append(parts, args...)
	parts = append(parts, "--settings-file", path)
	var program strings.Builder
	for _, part := range parts {
		program.WriteString("<string>")
		program.WriteString(xmlEscape(part))
		program.WriteString("</string>")
	}
	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>%s</string><key>ProgramArguments</key><array>%s</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n", xmlEscape(label), program.String())
}
func windowsTaskScript(exe, path, command string) string {
	taskName := "AI Relay ARPL " + strings.ReplaceAll(command, " ", "-")
	return fmt.Sprintf("$ErrorActionPreference='Stop'\n$exe='%s'\n$settings='%s'\n$action=New-ScheduledTaskAction -Execute $exe -Argument '%s --settings-file \"'+$settings+'\"'\n$trigger=New-ScheduledTaskTrigger -AtLogOn\nRegister-ScheduledTask -TaskName '%s' -Action $action -Trigger $trigger -Force | Out-Null\n", strings.ReplaceAll(exe, "'", "''"), strings.ReplaceAll(path, "'", "''"), command, taskName)
}
func termuxScript(exe, path string, s ARPLSettings) string {
	return fmt.Sprintf("#!/data/data/com.termux/files/usr/bin/sh\nset -eu\nexec '%s' client connect --settings-file '%s'\n", strings.ReplaceAll(exe, "'", "'\\''"), strings.ReplaceAll(path, "'", "'\\''"))
}

func applySettings(path, platform, outputDir string, dryRun bool) error {
	s, err := loadSettings(path)
	if err != nil {
		return err
	}
	if err = validateSettings(s); err != nil {
		return err
	}
	services, err := renderServices(s, path, platform)
	if err != nil {
		return err
	}
	activate := outputDir == ""
	if outputDir == "" {
		home, _ := os.UserHomeDir()
		switch platform {
		case "linux":
			outputDir = filepath.Join(home, ".config", "systemd", "user")
		case "darwin":
			outputDir = filepath.Join(home, "Library", "LaunchAgents")
		case "windows":
			outputDir = filepath.Join(home, "AppData", "Roaming", "AI Relay", "ARPL")
		default:
			outputDir = filepath.Join(filepath.Dir(path), "generated")
		}
	}
	if os.Getenv("ARPL_SERVICE_ACTIVATE") == "1" {
		activate = true
	}
	if dryRun {
		for _, v := range services {
			fmt.Printf("--- %s ---\n%s", v.Name, v.Content)
		}
		return nil
	}
	if err = os.MkdirAll(outputDir, 0700); err != nil {
		return err
	}
	backups := map[string][]byte{}
	existed := map[string]bool{}
	targetNames := make([]string, 0, len(services)+len(legacyLinuxServiceNames))
	for _, v := range services {
		targetNames = append(targetNames, v.Name)
	}
	if platform == "linux" {
		targetNames = append(targetNames, legacyLinuxServiceNames...)
	}
	for _, name := range targetNames {
		target := filepath.Join(outputDir, name)
		if b, e := os.ReadFile(target); e == nil {
			backups[target] = b
			existed[target] = true
			_ = os.WriteFile(target+".bak", b, 0600)
		} else if os.IsNotExist(e) {
			existed[target] = false
		}
	}
	restoreFiles := func() {
		for target, b := range backups {
			_ = os.WriteFile(target, b, 0600)
		}
		for target, wasThere := range existed {
			if !wasThere {
				_ = os.Remove(target)
			}
		}
	}
	for _, v := range services {
		target := filepath.Join(outputDir, v.Name)
		tmp, e := os.CreateTemp(outputDir, ".arpl-render-")
		if e != nil {
			restoreFiles()
			return e
		}
		tmpName := tmp.Name()
		if _, e = tmp.WriteString(v.Content); e == nil {
			e = tmp.Sync()
		}
		if e == nil {
			e = tmp.Chmod(v.Mode)
		}
		if ce := tmp.Close(); e == nil {
			e = ce
		}
		if e != nil {
			_ = os.Remove(tmpName)
			restoreFiles()
			return e
		}
		if e = os.Rename(tmpName, target); e != nil {
			restoreFiles()
			return e
		}
	}
	legacyEnabled := map[string]bool{}
	if activate && platform == "linux" {
		legacyEnabled = disableLegacyLinuxServices()
	}
	if activate {
		if err := activateServices(platform, outputDir, services); err != nil {
			deactivateServices(platform, outputDir, services)
			restoreFiles()
			restoreLegacyLinuxServices(legacyEnabled)
			return fmt.Errorf("service activation failed; files rolled back: %w", err)
		}
	}
	if activate && platform == "linux" {
		for _, name := range legacyLinuxServiceNames {
			_ = os.Remove(filepath.Join(outputDir, name))
		}
	}
	return nil
}

func deactivateServices(platform, dir string, services []renderedService) {
	switch platform {
	case "linux":
		if systemdUserUsable() {
			for _, service := range services {
				if strings.HasSuffix(service.Name, ".service") {
					_ = exec.Command("systemctl", "--user", "disable", "--now", service.Name).Run()
				}
			}
		}
		_ = removeARPLCronEntry()
	case "darwin":
		uid := os.Getenv("UID")
		if uid == "" {
			if b, err := exec.Command("id", "-u").Output(); err == nil {
				uid = strings.TrimSpace(string(b))
			}
		}
		if uid != "" {
			for _, service := range services {
				if strings.HasSuffix(service.Name, ".plist") {
					_ = exec.Command("launchctl", "bootout", "gui/"+uid+"/"+strings.TrimSuffix(service.Name, ".plist")).Run()
				}
			}
		}
	case "windows":
		for _, service := range services {
			if strings.HasSuffix(service.Name, ".ps1") {
				_ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-File", filepath.Join(dir, service.Name), "-Unregister").Run()
			}
		}
	}
}

func activateServices(platform, dir string, services []renderedService) error {
	switch platform {
	case "linux":
		if systemdUserUsable() {
			if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
				return err
			}
			for _, service := range services {
				if !strings.HasSuffix(service.Name, ".service") {
					continue
				}
				if err := exec.Command("systemctl", "--user", "enable", "--now", service.Name).Run(); err != nil {
					return err
				}
				if err := exec.Command("systemctl", "--user", "is-active", "--quiet", service.Name).Run(); err != nil {
					return fmt.Errorf("%s did not become active: %w", service.Name, err)
				}
			}
			return nil
		}
		return installARPLCron(services)
	case "darwin":
		uid := os.Getenv("UID")
		if uid == "" {
			if b, err := exec.Command("id", "-u").Output(); err == nil {
				uid = strings.TrimSpace(string(b))
			}
		}
		if uid == "" {
			return errors.New("unable to determine logged-in macOS user ID")
		}
		for _, service := range services {
			if !strings.HasSuffix(service.Name, ".plist") {
				continue
			}
			label := strings.TrimSuffix(service.Name, ".plist")
			if err := exec.Command("launchctl", "bootstrap", "gui/"+uid, filepath.Join(dir, service.Name)).Run(); err != nil {
				return err
			}
			if err := exec.Command("launchctl", "kickstart", "-k", "gui/"+uid+"/"+label).Run(); err != nil {
				return err
			}
		}
	case "windows":
		for _, service := range services {
			if err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(dir, service.Name)).Run(); err != nil {
				return err
			}
		}
	case "android":
		// The Android foreground service owns process activation. The generated
		// Termux script is an explicit bridge and is never started by a shell here.
		return nil
	}
	return nil
}

func systemdUserUsable() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "--user", "show-environment").Run() == nil
}

func disableLegacyLinuxServices() map[string]bool {
	wasEnabled := map[string]bool{}
	if !systemdUserUsable() {
		return wasEnabled
	}
	for _, name := range legacyLinuxServiceNames {
		if exec.Command("systemctl", "--user", "is-enabled", "--quiet", name).Run() == nil {
			wasEnabled[name] = true
		}
		_ = exec.Command("systemctl", "--user", "disable", "--now", name).Run()
	}
	return wasEnabled
}

func restoreLegacyLinuxServices(wasEnabled map[string]bool) {
	if len(wasEnabled) == 0 || !systemdUserUsable() {
		return
	}
	for name := range wasEnabled {
		_ = exec.Command("systemctl", "--user", "enable", "--now", name).Run()
	}
}

func readARPLCrontab() ([]byte, error) {
	if _, err := exec.LookPath("crontab"); err != nil {
		return nil, err
	}
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		// Vixie cron returns non-zero when the user has no crontab. Preserve
		// any output only if it contains an actual crontab; otherwise start
		// from an empty per-user table.
		if len(out) == 0 {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}

func installARPLCron(services []renderedService) error {
	current, err := readARPLCrontab()
	if err != nil {
		return fmt.Errorf("user systemd is unavailable and crontab cannot be read: %w", err)
	}
	lines := strings.Split(strings.TrimRight(string(current), "\n"), "\n")
	kept := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if strings.Contains(line, "# ai-relay-arpl-supervisor") || strings.TrimSpace(line) == "" {
			if strings.TrimSpace(line) == "" {
				kept = append(kept, line)
			}
			continue
		}
		kept = append(kept, line)
	}
	entry := ""
	for _, service := range services {
		if service.Name == "arpl-supervisor.cron" {
			entry = strings.TrimSpace(service.Content)
			break
		}
	}
	if entry == "" {
		return errors.New("ARPL supervisor cron entry was not rendered")
	}
	kept = append(kept, entry)
	return writeARPLCrontab([]byte(strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"))
}

func removeARPLCronEntry() error {
	current, err := readARPLCrontab()
	if err != nil || len(current) == 0 {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(current), "\n"), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.Contains(line, "# ai-relay-arpl-supervisor") {
			kept = append(kept, line)
		}
	}
	return writeARPLCrontab([]byte(strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"))
}

func writeARPLCrontab(data []byte) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(string(data))
	return cmd.Run()
}
