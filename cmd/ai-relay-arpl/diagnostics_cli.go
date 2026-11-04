package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ai-relay/ai-relay/internal/arpl"
)

type diagnostic struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func doctorCommand(args []string) {
	f := flag.NewFlagSet("doctor", flag.ExitOnError)
	path := defaultSettingsPath()
	jsonOut := false
	f.StringVar(&path, "settings-file", path, "settings file")
	f.BoolVar(&jsonOut, "json", false, "machine-readable output")
	_ = f.Parse(args)
	out := []diagnostic{}
	add := func(c, s, d string) { out = append(out, diagnostic{c, s, d}) }
	s, err := loadSettings(path)
	if err != nil {
		add("settings", "FAIL", "unable to load settings")
	} else if err = validateSettings(s); err != nil {
		add("settings", "FAIL", "invalid settings: "+err.Error())
	} else {
		add("settings", "PASS", "schema and values valid")
		if s.Host.FileRoot == "" {
			add("file_root", "WARN", "remote file and sync operations are disabled")
		} else if st, statErr := os.Stat(s.Host.FileRoot); statErr != nil || !st.IsDir() {
			add("file_root", "FAIL", "configured file root is not an accessible directory")
		} else {
			add("file_root", "PASS", "configured file root is accessible")
		}
		if s.Relay.Listen != "" {
			if host, _, splitErr := net.SplitHostPort(s.Relay.Listen); splitErr == nil && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() {
				conn, dialErr := net.DialTimeout("tcp", s.Relay.Listen, 250*time.Millisecond)
				if dialErr == nil {
					_ = conn.Close()
					add("local_listener", "PASS", "configured local ARPL listener accepted a connection")
				} else {
					add("local_listener", "WARN", "configured local ARPL listener is not running")
				}
			} else {
				add("local_listener", "WARN", "local listener is not a loopback host:port")
			}
		}
		if len(s.Peers) == 0 {
			add("peers", "WARN", "no enrolled peers are configured")
		} else {
			add("peers", "PASS", fmt.Sprintf("%d peer profile(s) configured", len(s.Peers)))
		}
	}
	if id, err := load(s.Security.KeyFile); err != nil {
		add("identity", "WARN", "identity unavailable")
	} else if id.Validate() == nil {
		add("identity", "PASS", "identity and owner-only key validated")
	}
	if u, err := url.Parse(s.Relay.URL); err == nil && u.Host != "" {
		if _, err = net.LookupHost(u.Hostname()); err != nil {
			add("relay_dns", "WARN", "relay hostname did not resolve")
		} else {
			add("relay_dns", "PASS", "relay hostname resolves")
		}
	} else {
		add("relay_dns", "WARN", "relay URL not configured")
	}
	generated := filepath.Join(filepath.Dir(path), "generated")
	if _, err = os.Stat(generated); err == nil {
		add("service_persistence", "PASS", "generated service configuration exists")
	} else {
		add("service_persistence", "WARN", "run settings apply to render native persistence")
	}
	add("platform", "PASS", runtime.GOOS+"/"+runtime.GOARCH)
	if jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(out)
	} else {
		for _, v := range out {
			fmt.Printf("%-7s %-20s %s\n", v.Status, v.Check, v.Detail)
		}
	}
}

func fleetCommand(args []string) {
	f := flag.NewFlagSet("fleet", flag.ExitOnError)
	path := defaultSettingsPath()
	jsonOut := false
	f.StringVar(&path, "settings-file", path, "settings file")
	f.BoolVar(&jsonOut, "json", false, "machine-readable output")
	_ = f.Parse(args)
	s, err := loadSettings(path)
	if err != nil {
		fatal(err)
	}
	store := &arpl.FleetStore{Path: filepath.Join(filepath.Dir(path), "fleet.json")}
	records, _ := store.List()
	byID := map[string]arpl.FleetRecord{}
	for _, r := range records {
		byID[r.DeviceID] = r
	}
	type row struct {
		Name, OS, Arch, Role, Status, Path, Version, BuildHash string
		Enabled                                                bool
		Capabilities                                           []string
		LastConnect                                            string
		LatencyMS                                              int64
	}
	rows := make([]row, 0, len(s.Peers))
	for _, p := range s.Peers {
		status := "offline"
		osName, arch, pathName, version, buildHash := "unknown", "unknown", "relay", "", ""
		caps := p.Capabilities
		last := ""
		latency := int64(0)
		if p.Enabled && p.AutoConnect {
			status = "configured"
		}
		if pub, e := decodePublic(p.PublicKey); e == nil {
			if r, ok := byID[arpl.DeviceID(pub)]; ok {
				if r.Connected {
					status = "online"
				}
				osName = r.OS
				arch = r.Arch
				pathName = r.Path
				version = r.Version
				buildHash = r.BuildHash
				if len(r.Capabilities) > 0 {
					caps = r.Capabilities
				}
				if !r.LastConnect.IsZero() {
					last = r.LastConnect.UTC().Format(time.RFC3339)
				}
				latency = r.LatencyMS
			}
		}
		rows = append(rows, row{p.Name, osName, arch, "peer", status, pathName, version, buildHash, p.Enabled, caps, last, latency})
	}
	if jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(rows)
		return
	}
	fmt.Println("NAME\tSTATUS\tOS/ARCH\tPATH\tLATENCY\tVERSION\tENABLED")
	for _, r := range rows {
		fmt.Printf("%s\t%s\t%s/%s\t%s\t%dms\t%s\t%t\n", r.Name, r.Status, r.OS, r.Arch, r.Path, r.LatencyMS, r.Version, r.Enabled)
	}
}

func auditCommand(args []string) {
	if len(args) == 0 || args[0] != "query" {
		fatal(errors.New("audit requires query"))
	}
	f := flag.NewFlagSet("audit query", flag.ExitOnError)
	path := ""
	jsonOut := false
	f.StringVar(&path, "file", "", "audit JSONL file")
	f.BoolVar(&jsonOut, "json", false, "machine-readable output")
	_ = f.Parse(args[1:])
	if path == "" {
		fatal(errors.New("-file is required"))
	}
	if err := arpl.QueryAudit(path, os.Stdout, jsonOut); err != nil {
		fatal(err)
	}
}

func syncCommand(args []string) {
	f := flag.NewFlagSet("sync", flag.ExitOnError)
	var o clientOptions
	o.addFlags(f)
	src, dst, includes, excludes := "", "", "", ""
	del := false
	f.StringVar(&src, "src", "", "local source directory")
	f.StringVar(&dst, "dest", "", "remote destination directory relative to the server file root")
	f.StringVar(&includes, "include", "", "comma-separated include globs")
	f.StringVar(&excludes, "exclude", "", "comma-separated exclude globs")
	f.BoolVar(&del, "delete", false, "delete destination files absent from source")
	_ = f.Parse(args)
	if src == "" || dst == "" {
		fatal(errors.New("sync requires -src, -dest, and ARPL connection flags"))
	}
	opt := arpl.SyncOptions{Include: splitList(includes), Exclude: splitList(excludes)}
	local, err := arpl.BuildSyncManifest(src, opt)
	if err != nil {
		fatal(err)
	}
	c, err := openRPC(o)
	if err != nil {
		fatal(err)
	}
	defer c.Close()
	if err = c.send(arpl.ChannelFile, arpl.OpMessage{Action: "sync_manifest", Src: dst, Include: opt.Include, Exclude: opt.Exclude}); err != nil {
		fatal(err)
	}
	remoteResponse, err := c.recv()
	if err != nil {
		fatal(err)
	}
	if remoteResponse.Error != "" || !remoteResponse.OK {
		fatal(errors.New(remoteResponse.Error))
	}
	var remote arpl.SyncManifest
	if err = json.Unmarshal([]byte(remoteResponse.Manifest), &remote); err != nil {
		fatal(err)
	}
	remoteByPath := make(map[string]arpl.SyncEntry, len(remote.Entries))
	for _, entry := range remote.Entries {
		remoteByPath[entry.Path] = entry
	}
	for _, entry := range local.Entries {
		if entry.Symlink {
			fatal(fmt.Errorf("sync refuses symlink %s", entry.Path))
		}
		if old, ok := remoteByPath[entry.Path]; ok && old.Size == entry.Size && strings.EqualFold(old.SHA256, entry.SHA256) {
			continue
		}
		base := ""
		if old, ok := remoteByPath[entry.Path]; ok {
			base = old.SHA256
		}
		localPath := filepath.Join(src, filepath.FromSlash(entry.Path))
		remotePath := filepath.ToSlash(filepath.Join(dst, filepath.FromSlash(entry.Path)))
		if err = remoteUpload(c, localPath, remotePath, entry, base); err != nil {
			fatal(err)
		}
	}
	if del {
		b, _ := json.Marshal(local)
		if err = c.send(arpl.ChannelFile, arpl.OpMessage{Action: "sync_delete", Src: dst, Manifest: string(b), Delete: true, Include: opt.Include, Exclude: opt.Exclude}); err != nil {
			fatal(err)
		}
		deleted, recvErr := c.recv()
		if recvErr != nil {
			fatal(recvErr)
		}
		if deleted.Error != "" || !deleted.OK {
			fatal(errors.New(deleted.Error))
		}
	}
	if err := c.store.Save(context.Background(), c.state); err != nil {
		fatal(err)
	}
	fmt.Printf("sync complete path=%s latency_ms=%d\n", c.route.Kind, c.route.Latency.Milliseconds())
}

func remoteUpload(c *rpcClient, src, dest string, entry arpl.SyncEntry, base string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = c.send(arpl.ChannelFile, arpl.OpMessage{Action: "upload_begin", Dest: dest, Size: entry.Size, SHA256: entry.SHA256, BaseSHA256: base, Replace: true, Mode: entry.Mode}); err != nil {
		return err
	}
	ready, err := c.recv()
	if err != nil {
		return err
	}
	if ready.Error != "" {
		return errors.New(ready.Error)
	}
	if ready.Done && ready.OK {
		return nil
	}
	if ready.Offset < 0 || ready.Offset > entry.Size {
		return errors.New("server returned invalid sync resume offset")
	}
	if _, err = f.Seek(ready.Offset, io.SeekStart); err != nil {
		return err
	}
	offset := ready.Offset
	buf := make([]byte, arpl.DefaultChunkSize)
	for offset < entry.Size {
		n, readErr := f.Read(buf)
		if n > 0 {
			if err = c.send(arpl.ChannelFile, arpl.OpMessage{Action: "upload_chunk", Offset: offset, Data: base64.RawStdEncoding.EncodeToString(buf[:n])}); err != nil {
				return err
			}
			ack, recvErr := c.recv()
			if recvErr != nil {
				return recvErr
			}
			if ack.Error != "" {
				return errors.New(ack.Error)
			}
			offset = ack.Offset
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if offset != entry.Size {
		return errors.New("local sync source ended at unexpected size")
	}
	if err = c.send(arpl.ChannelFile, arpl.OpMessage{Action: "upload_finish"}); err != nil {
		return err
	}
	done, err := c.recv()
	if err != nil {
		return err
	}
	if done.Error != "" || !done.OK {
		return errors.New(done.Error)
	}
	return nil
}
func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, x := range strings.Split(v, ",") {
		if strings.TrimSpace(x) != "" {
			out = append(out, strings.TrimSpace(x))
		}
	}
	return out
}

func jobCommand(args []string) {
	if len(args) == 0 {
		fatal(errors.New("job requires run|status|logs|cancel|list"))
	}
	op := args[0]
	f := flag.NewFlagSet("job", flag.ExitOnError)
	var o clientOptions
	o.addFlags(f)
	id := ""
	timeout := int64(0)
	f.StringVar(&id, "id", "", "job ID")
	f.Int64Var(&timeout, "timeout-ms", timeout, "job timeout")
	_ = f.Parse(args[1:])
	c, err := openRPC(o)
	if err != nil {
		fatal(err)
	}
	defer c.Close()
	msg := arpl.OpMessage{Action: "job_" + op, JobID: id, TimeoutMS: timeout, Argv: f.Args()}
	if err = c.send(arpl.ChannelTool, msg); err != nil {
		fatal(err)
	}
	resp, err := c.recv()
	if err != nil {
		fatal(err)
	}
	b, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(b))
	if !resp.OK && resp.Error != "" {
		os.Exit(1)
	}
}

func updateCommand(args []string) {
	f := flag.NewFlagSet("update", flag.ExitOnError)
	artifact, manifestPath, target, pubHex := "", "", "", ""
	f.StringVar(&artifact, "artifact", "", "candidate artifact")
	f.StringVar(&manifestPath, "manifest", "", "signed release manifest JSON")
	f.StringVar(&target, "target", "", "installed binary target")
	f.StringVar(&pubHex, "public-key", "", "release signer public key hex")
	_ = f.Parse(args)
	if artifact == "" || manifestPath == "" || target == "" || pubHex == "" {
		fatal(errors.New("update requires -artifact -manifest -target -public-key"))
	}
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		fatal(err)
	}
	var m arpl.ReleaseManifest
	if err = json.Unmarshal(b, &m); err != nil {
		fatal(err)
	}
	raw, err := hex.DecodeString(pubHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		fatal(errors.New("invalid release public key"))
	}
	if err = arpl.StageAndActivateUpdate(artifact, m, ed25519.PublicKey(raw), arpl.UpdateOptions{Target: target}); err != nil {
		fatal(err)
	}
	fmt.Println("update activated")
}
