package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	supervisorDirName  = ".arpl-supervisor"
	stopMarkerDirName  = "stopped"
	supervisorLockName = "supervisor.lock"
	supervisorPIDName  = "supervisor.pid"
	stableChildRuntime = 30 * time.Second
	minChildBackoff    = time.Second
	maxChildBackoff    = 60 * time.Second
)

// supervisorPaths are deliberately derived from the settings directory and a
// peer public-key hash. They are safe across peer renames and do not put peer
// names or secrets in filenames.
type supervisorPaths struct {
	Session string
	Control string
	Marker  string
}

func supervisorStateDir(settingsPath string) string {
	return filepath.Join(filepath.Dir(settingsPath), supervisorDirName)
}

func peerSupervisorID(p PeerSettings) string {
	v := strings.TrimSpace(p.PublicKey)
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(p.Name))
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func peerSupervisorPaths(settingsPath string, p PeerSettings) supervisorPaths {
	id := peerSupervisorID(p)
	peerDir := filepath.Join(supervisorStateDir(settingsPath), "peers", id)
	session := p.SessionFile
	if session == "" {
		session = filepath.Join(peerDir, "session.json")
	}
	control := p.ControlState
	if control == "" {
		control = filepath.Join(peerDir, "control.json")
	}
	return supervisorPaths{
		Session: session,
		Control: control,
		Marker:  filepath.Join(supervisorStateDir(settingsPath), stopMarkerDirName, id+".marker"),
	}
}

func peerStopMarker(settingsPath string, p PeerSettings) string {
	return peerSupervisorPaths(settingsPath, p).Marker
}

func peerStopMarkerForKey(settingsPath, publicKey string) (string, bool) {
	s, err := loadSettings(settingsPath)
	if err != nil {
		return "", false
	}
	for _, p := range s.Peers {
		if peerKeyEqual(p.PublicKey, publicKey) {
			return peerStopMarker(settingsPath, p), true
		}
	}
	return "", false
}

func peerKeyEqual(a, b string) bool {
	if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) {
		return true
	}
	left, leftErr := decodePublic(a)
	right, rightErr := decodePublic(b)
	return leftErr == nil && rightErr == nil && left.Equal(right)
}

func writePeerStopMarker(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("intentional disconnect\n"), 0600)
}

func clearPeerStopMarker(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func peerStopMarked(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type supervisorChild struct {
	Key  string
	Role string
	Args []string
}

// supervisionPlans is the single source of truth for child cardinality. A
// child always receives an explicit peer key and pair; it never selects a peer
// by rereading the settings file's first enabled entry.
func supervisionPlans(s ARPLSettings, settingsPath, exe string) []supervisorChild {
	var plans []supervisorChild
	for _, p := range s.Peers {
		if !p.Enabled || strings.TrimSpace(p.PublicKey) == "" {
			continue
		}
		id := peerSupervisorID(p)
		paths := peerSupervisorPaths(settingsPath, p)
		relayURL := p.RelayURL
		if relayURL == "" {
			relayURL = s.Relay.URL
		}
		tokenFile := s.Security.RelayTokenFile
		if s.Service.StartHost && s.Host.Enabled && p.InboundPair != "" {
			args := []string{"host", "run", "--settings-file", settingsPath, "--peer-key", p.PublicKey, "--relay-pair", p.InboundPair}
			if relayURL != "" {
				args = append(args, "--relay-url", relayURL)
			}
			if tokenFile != "" {
				args = append(args, "--relay-token-file", tokenFile)
			}
			plans = append(plans, supervisorChild{Key: id + ":host", Role: "host", Args: args})
		}
		if s.Service.StartClient && s.Client.Enabled && p.OutboundPair != "" && !peerStopMarked(paths.Marker) {
			heartbeat := p.Heartbeat
			if heartbeat == "" {
				heartbeat = s.Client.Heartbeat
			}
			args := []string{"client", "connect", "--settings-file", settingsPath, "--peer-key", p.PublicKey, "--relay-pair", p.OutboundPair, "--session-file", paths.Session, "--control-state", paths.Control, "--intentional-stop-marker", paths.Marker, "--heartbeat", heartbeat}
			if relayURL != "" {
				args = append(args, "--relay-url", relayURL)
			}
			if tokenFile != "" {
				args = append(args, "--relay-token-file", tokenFile)
			}
			plans = append(plans, supervisorChild{Key: id + ":client", Role: "client", Args: args})
		}
	}
	return plans
}

type supervisorExit struct {
	key     string
	started time.Time
}

type managedChild struct {
	spec      supervisorChild
	cmd       *exec.Cmd
	started   time.Time
	backoff   time.Duration
	nextStart time.Time
}

var errSupervisorAlreadyRunning = errors.New("ARPL supervisor is already running")

func supervisorRun(args []string) {
	settingsPath := defaultSettingsPath()
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--settings-file" || args[i] == "--file" {
			settingsPath = args[i+1]
			break
		}
	}
	if settingsPath == "" {
		fatal(errors.New("supervisor requires --settings-file"))
	}
	if err := runSupervisor(context.Background(), settingsPath); err != nil && !errors.Is(err, context.Canceled) {
		fatal(err)
	}
}

func runSupervisor(parent context.Context, settingsPath string) error {
	if s, err := loadSettings(settingsPath); err != nil {
		return err
	} else if err = validateSettings(s); err != nil {
		return err
	}
	lock, err := acquireSupervisorLock(supervisorStateDir(settingsPath))
	if err != nil {
		return err
	}
	defer lock.Release()

	exe := currentARPLExecutable()
	ctx, cancel := supervisorSignalContext(parent)
	defer cancel()
	exits := make(chan supervisorExit, 32)
	children := map[string]*managedChild{}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	stopChild := func(child *managedChild) {
		if child == nil || child.cmd == nil || child.cmd.Process == nil {
			return
		}
		_ = child.cmd.Process.Kill()
	}
	stopAll := func() {
		for key, child := range children {
			if child == nil || child.cmd == nil {
				delete(children, key)
				continue
			}
			stopChild(child)
		}
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for len(children) > 0 {
			select {
			case exit := <-exits:
				if _, ok := children[exit.key]; ok {
					delete(children, exit.key)
				}
			case <-deadline.C:
				return
			}
		}
	}

	reconcile := func() error {
		current, err := loadSettings(settingsPath)
		if err != nil {
			return err
		}
		if err = validateSettings(current); err != nil {
			return err
		}
		wanted := supervisionPlans(current, settingsPath, exe)
		wantedByKey := make(map[string]supervisorChild, len(wanted))
		for _, spec := range wanted {
			wantedByKey[spec.Key] = spec
		}
		for key, child := range children {
			spec, ok := wantedByKey[key]
			if !ok || !reflect.DeepEqual(spec.Args, child.spec.Args) {
				stopChild(child)
				delete(children, key)
			}
		}
		now := time.Now()
		for _, spec := range wanted {
			child := children[spec.Key]
			if child == nil {
				child = &managedChild{spec: spec, backoff: minChildBackoff}
				children[spec.Key] = child
			}
			if child.cmd != nil || now.Before(child.nextStart) {
				continue
			}
			cmd := exec.Command(exe, spec.Args...)
			configureSupervisedChild(cmd)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Start(); err != nil {
				child.nextStart = now.Add(child.backoff)
				child.backoff = nextChildBackoff(child.backoff)
				continue
			}
			child.cmd = cmd
			child.started = now
			go func(key string, started time.Time, command *exec.Cmd) {
				_ = command.Wait()
				exits <- supervisorExit{key: key, started: started}
			}(spec.Key, now, cmd)
		}
		return nil
	}

	if err = reconcile(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			stopAll()
			return ctx.Err()
		case exit := <-exits:
			child := children[exit.key]
			if child == nil || child.started != exit.started {
				continue
			}
			child.cmd = nil
			if time.Since(exit.started) >= stableChildRuntime {
				child.backoff = minChildBackoff
			}
			child.nextStart = time.Now().Add(child.backoff)
			child.backoff = nextChildBackoff(child.backoff)
		case <-ticker.C:
			if err := reconcile(); err != nil {
				stopAll()
				return err
			}
		}
	}
}

func nextChildBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return minChildBackoff
	}
	if current >= maxChildBackoff/2 {
		return maxChildBackoff
	}
	return current * 2
}

type supervisorLock struct {
	dir  string
	once sync.Once
}

func acquireSupervisorLock(stateDir string) (*supervisorLock, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	lockDir := filepath.Join(stateDir, supervisorLockName)
	pidFile := filepath.Join(lockDir, supervisorPIDName)
	for attempt := 0; attempt < 2; attempt++ {
		if err := os.Mkdir(lockDir, 0700); err == nil {
			if err = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0600); err != nil {
				_ = os.RemoveAll(lockDir)
				return nil, err
			}
			return &supervisorLock{dir: lockDir}, nil
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		b, readErr := os.ReadFile(pidFile)
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(b)))
		if readErr == nil && parseErr == nil && pid > 0 && supervisorProcessAlive(pid) {
			return nil, fmt.Errorf("%w (pid %d)", errSupervisorAlreadyRunning, pid)
		}
		// A missing, malformed, or dead PID makes this a stale lock. Rename
		// it out of the live lock name before removing it; that preserves the
		// atomic lock boundary if two fallback invocations recover together.
		staleDir := lockDir + ".stale-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if err := os.Rename(lockDir, staleDir); err != nil {
			continue
		}
		if err := os.RemoveAll(staleDir); err != nil {
			return nil, err
		}
	}
	return nil, errSupervisorAlreadyRunning
}

func (l *supervisorLock) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		_ = os.Remove(filepath.Join(l.dir, supervisorPIDName))
		_ = os.Remove(l.dir)
	})
}
