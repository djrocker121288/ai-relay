package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ai-relay/ai-relay/internal/agentcore"
	"github.com/ai-relay/ai-relay/internal/distribution"
	"github.com/ai-relay/ai-relay/internal/protocol"
	"github.com/ai-relay/ai-relay/internal/security"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type client struct {
	base, id, secret string
	hc               *http.Client
	outbox           string
	mu               sync.Mutex
}

func (c *client) request(method string, params any, out any) error {
	id, _ := security.Token(12)
	nonce, _ := security.Token(18)
	ts := time.Now().Unix()
	q := protocol.Request{Version: protocol.Version, ID: id, DeviceID: c.id, Timestamp: ts, Nonce: nonce, Method: method, Params: params}
	q.Signature = security.Sign(c.secret, q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(params))
	b, _ := json.Marshal(q)
	resp, e := c.hc.Post(security.GatewayEndpoint(c.base, "v1/agent/"+map[string]string{"agent.poll": "poll", "agent.result": "result"}[method]), "application/json", bytes.NewReader(b))
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		x, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("gateway %s: %s", resp.Status, string(x))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16*1024*1024)).Decode(out)
}
func paramsBytes(v any) []byte { b, _ := json.Marshal(v); return b }
func enroll(base, token string) (string, string, error) {
	b, _ := json.Marshal(map[string]string{"name": runtime.GOOS, "platform": runtime.GOOS, "arch": runtime.GOARCH, "token": token})
	r, e := http.Post(security.GatewayEndpoint(base, "v1/enroll"), "application/json", bytes.NewReader(b))
	if e != nil {
		return "", "", e
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("enrollment failed: %s", r.Status)
	}
	var x struct {
		DeviceID string `json:"device_id"`
		Secret   string `json:"secret"`
	}
	e = json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&x)
	if e == nil && (x.DeviceID == "" || x.Secret == "") {
		e = fmt.Errorf("gateway returned invalid enrollment credentials")
	}
	return x.DeviceID, x.Secret, e
}
func main() {
	gateway := flag.String("gateway", "http://127.0.0.1:8743", "gateway URL")
	credentialFile := flag.String("credential-file", "", "0600 file containing device_id and secret")
	tokenFile := flag.String("enroll-token-file", "", "0600 file containing a one-use enrollment token")
	enrollOnly := flag.Bool("enroll-only", false, "enroll with -enroll-token-file, write the credential, and exit without polling")
	once := flag.Bool("once", false, "poll once and exit")
	cmd := flag.String("command", "", "one-shot command")
	updateOrigin := flag.String("update-origin", "", "HTTPS update origin (required for signed update checks)")
	updateKey := flag.String("update-key", "", "pinned Ed25519 update public key (hex or base64)")
	checkUpdate := flag.Bool("check-update", false, "check for a signed update and show release notes")
	installUpdate := flag.Bool("install-update", false, "download and install the checked update; explicit user approval")
	dryRunUpdate := flag.Bool("update-dry-run", false, "verify a signed update and local install boundary without changing files")
	rollbackUpdate := flag.Bool("rollback-update", false, "restore the previous verified executable")
	telemetryOptIn := flag.Bool("telemetry-opt-in", false, "explicitly enable aggregate usage telemetry")
	telemetryOff := flag.Bool("telemetry-off", false, "disable aggregate usage telemetry")
	telemetryStatus := flag.Bool("telemetry-status", false, "show local telemetry setting and exact payload shape")
	telemetrySend := flag.Bool("telemetry-send", false, "send one aggregate heartbeat after opt-in")
	telemetryEndpoint := flag.String("telemetry-endpoint", "", "HTTPS telemetry endpoint (required only when sending)")
	telemetryFile := flag.String("telemetry-file", "", "0600 telemetry config (default under user config)")
	reportPreview := flag.Bool("report-preview", false, "generate and print a redacted diagnostic bundle")
	reportSubmit := flag.Bool("report-submit", false, "submit the displayed redacted diagnostic bundle after explicit approval")
	reportEndpoint := flag.String("report-endpoint", "", "HTTPS issue report endpoint (required only when submitting)")
	flag.Parse()
	if *enrollOnly && *tokenFile == "" {
		log.Fatal("-enroll-only requires -enroll-token-file")
	}
	configFile := *telemetryFile
	if configFile == "" {
		if d, err := os.UserConfigDir(); err == nil {
			configFile = d + "/ai-relay/telemetry.json"
		} else {
			configFile = "./telemetry.json"
		}
	}
	if *rollbackUpdate {
		exe, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		if err = distribution.Rollback(exe); err != nil {
			log.Fatal(err)
		}
		fmt.Println("rollback installed; restart AI Relay to use it")
		return
	}
	if *checkUpdate || *installUpdate || *dryRunUpdate {
		if *updateOrigin == "" {
			log.Fatal("-update-origin is required for update checks")
		}
		if *installUpdate && *dryRunUpdate {
			log.Fatal("-install-update and -update-dry-run cannot be combined")
		}
		if *updateKey == "" {
			log.Fatal("-update-key is required for signed update checks")
		}
		key, err := distribution.DecodePinnedKey(*updateKey)
		if err != nil {
			log.Fatal(err)
		}
		uc := distribution.Client{Origin: *updateOrigin, PublicKey: key}
		m, err := uc.Check(context.Background(), distribution.Version)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("available version: %s\nrelease notes: %s\nartifact: %s\n", m.Version, m.ReleaseNotes, m.ArtifactURL)
		if *installUpdate {
			b, err := uc.Download(context.Background(), m)
			if err != nil {
				log.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				log.Fatal(err)
			}
			if err = distribution.Install(exe, b, m.Version, distribution.Version); err != nil {
				log.Fatal(err)
			}
			fmt.Println("update installed; restart AI Relay to use it")
		}
		if *dryRunUpdate {
			b, err := uc.Download(context.Background(), m)
			if err != nil {
				log.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				log.Fatal(err)
			}
			if err = distribution.ValidateInstall(exe, int64(len(b)), m.Version, distribution.Version); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("update dry-run passed; no files changed; artifact bytes: %d\n", len(b))
		}
		return
	}
	if *telemetryOptIn || *telemetryOff || *telemetryStatus || *telemetrySend {
		if *telemetryOptIn || *telemetryOff {
			c, err := distribution.SetTelemetry(configFile, *telemetryOptIn)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("telemetry enabled=%t installation_id=%s\n", c.Enabled, c.InstallationID)
		}
		if *telemetryStatus {
			c, err := distribution.LoadTelemetry(configFile)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("telemetry enabled=%t; sends only installation_id, version, platform, architecture, first_seen, last_seen\n", c.Enabled)
		}
		if *telemetrySend {
			if *telemetryEndpoint == "" {
				log.Fatal("-telemetry-endpoint is required with -telemetry-send")
			}
			if err := distribution.SendTelemetry(context.Background(), *telemetryEndpoint, configFile, nil); err != nil {
				log.Fatal(err)
			}
			fmt.Println("telemetry heartbeat sent")
		}
		return
	}
	if *reportPreview || *reportSubmit {
		b := distribution.NewDiagnostic(agentcore.New().Capabilities(), "agent process available", nil)
		raw, err := b.JSON()
		if err != nil {
			log.Fatal(err)
		}
		if *reportPreview {
			fmt.Println(string(raw))
		}
		if *reportSubmit {
			if *reportEndpoint == "" {
				log.Fatal("-report-endpoint is required with -report-submit")
			}
			if !*reportPreview {
				fmt.Println(string(raw))
			}
			fmt.Println("report submission approved by -report-submit; uploading...")
			if err = distribution.SubmitReport(context.Background(), *reportEndpoint, b, true, nil); err != nil {
				log.Fatal(err)
			}
			fmt.Println("report submitted")
		}
		return
	}
	if *cmd != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		r, e := agentcore.New().Run(ctx, "local", *cmd, flag.Args(), ".", nil, false)
		fmt.Printf("%s\n", agentcore.JSON(r))
		if e != nil {
			os.Exit(1)
		}
		return
	}
	if err := security.LoopbackHTTP(*gateway); err != nil {
		log.Fatal(err)
	}
	id, secret := "", ""
	if *credentialFile != "" && *tokenFile == "" {
		b, err := security.ReadSecretFile(*credentialFile)
		if err != nil {
			log.Fatal(err)
		}
		var c struct {
			DeviceID string `json:"device_id"`
			Secret   string `json:"secret"`
		}
		if err := json.Unmarshal([]byte(b), &c); err != nil || c.DeviceID == "" || c.Secret == "" {
			log.Fatal("invalid agent credential file")
		}
		id, secret = c.DeviceID, c.Secret
	}
	if *tokenFile != "" {
		if *credentialFile == "" {
			log.Fatal("-credential-file is required with -enroll-token-file")
		}
		token, err := security.ReadSecretFile(*tokenFile)
		if err != nil {
			log.Fatal(err)
		}
		var enrollErr error
		id, secret, enrollErr = enroll(*gateway, token)
		if enrollErr != nil {
			log.Fatal(enrollErr)
		}
		b, _ := json.Marshal(struct {
			DeviceID string `json:"device_id"`
			Secret   string `json:"secret"`
		}{id, secret})
		f, err := os.OpenFile(*credentialFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatal(err)
		}
		if err = security.ProtectFile(*credentialFile); err != nil {
			f.Close()
			log.Fatal(err)
		}
		if _, err = f.Write(append(b, '\n')); err != nil {
			f.Close()
			log.Fatal(err)
		}
		if err = f.Close(); err != nil {
			log.Fatal(err)
		}
		log.Printf("agent enrollment complete; credential written to %s", *credentialFile)
		if *enrollOnly {
			return
		}
	}
	if id == "" || secret == "" {
		fmt.Printf("ai-relay-agent platform=%s capabilities=%v\n", runtime.GOOS, agentcore.New().Capabilities())
		return
	}
	c := &client{base: *gateway, id: id, secret: secret, outbox: *credentialFile + ".results", hc: &http.Client{Timeout: 35 * time.Second}}
	core := agentcore.New()
	for {
		c.flushResults()
		var x struct {
			Command *protocol.Command `json:"command"`
		}
		e := c.request("agent.poll", map[string]any{}, &x)
		if e != nil {
			time.Sleep(time.Second)
			continue
		}
		if x.Command != nil {
			handle(c, core, x.Command)
		}
		if *once {
			return
		}
		if x.Command == nil {
			time.Sleep(time.Second)
		}
	}
}
func handle(c *client, core *agentcore.Core, cmd *protocol.Command) {
	if cmd.Method == "agent.cancel" {
		_ = core.Cancel(cmd.JobID)
		_, _ = c.postResult(protocol.CommandResult{JobID: cmd.JobID, Result: map[string]any{"canceled": true}})
		return
	}
	if cmd.Method == "agent.stdin" {
		if p, ok := cmd.Params.(map[string]any); ok {
			if data, ok := p["data"].(string); ok {
				_ = core.WriteStdin(cmd.JobID, []byte(data))
			}
		}
		return
	}
	if cmd.Method != "agent.exec" {
		return
	}
	p, _ := cmd.Params.(map[string]any)
	if privileged, _ := p["privileged"].(bool); privileged {
		_, err := c.postResult(protocol.CommandResult{JobID: cmd.JobID, Error: "privileged execution is unsupported by the portable asynchronous agent"})
		if err != nil {
			log.Printf("result delivery deferred: %v", err)
		}
		return
	}
	name, _ := p["command"].(string)
	var args []string
	if a, ok := p["args"].([]any); ok {
		for _, v := range a {
			if s, ok := v.(string); ok {
				args = append(args, s)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	cwd, _ := p["cwd"].(string)
	env := map[string]string{}
	if values, ok := p["env"].(map[string]any); ok {
		for key, value := range values {
			if text, ok := value.(string); ok {
				env[key] = text
			}
		}
	}
	j, e := core.Start(ctx, cmd.JobID, name, args, cwd, env)
	if e != nil {
		cancel()
		_, _ = c.postResult(protocol.CommandResult{JobID: cmd.JobID, Error: e.Error()})
		return
	}
	go func() {
		defer cancel()
		for {
			time.Sleep(50 * time.Millisecond)
			{
				x := j.Snapshot()
				if x.Finished {
					_, _ = c.postResult(protocol.CommandResult{JobID: cmd.JobID, Result: map[string]any{"exit_code": func() int {
						if x.Exit == nil {
							return -1
						}
						return *x.Exit
					}(), "stdout": x.Stdout, "stderr": x.Stderr, "stdout_truncated": x.StdoutTruncated, "stderr_truncated": x.StderrTruncated}})
					return
				}
			}
		}
	}()
}
func (c *client) postResult(v protocol.CommandResult) (map[string]any, error) {
	var out map[string]any
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outbox == "" {
		e := c.request("agent.result", v, &out)
		return out, e
	}
	if err := os.MkdirAll(c.outbox, 0700); err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(c.outbox, v.JobID+".json")
	if err := os.WriteFile(path+".tmp", b, 0600); err != nil {
		return nil, err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return nil, err
	}
	e := c.request("agent.result", v, &out)
	if e == nil {
		e = os.Remove(path)
	}
	return out, e
}

// flushResults replays completed results after outages and process restarts.
func (c *client) flushResults() {
	c.mu.Lock()
	defer c.mu.Unlock()
	entries, err := os.ReadDir(c.outbox)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(c.outbox, entry.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var result protocol.CommandResult
		if json.Unmarshal(b, &result) != nil {
			continue
		}
		var out map[string]any
		if c.request("agent.result", result, &out) != nil {
			return
		}
		if err := os.Remove(path); err != nil {
			log.Printf("result cleanup: %v", err)
		}
	}
}
