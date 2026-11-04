package arpl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type SyncEntry struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	SHA256  string `json:"sha256"`
	Symlink bool   `json:"symlink,omitempty"`
}
type SyncManifest struct {
	Root    string      `json:"root"`
	Entries []SyncEntry `json:"entries"`
}
type SyncOptions struct {
	Include        []string
	Exclude        []string
	FollowSymlinks bool
	MaxFileSize    int64
	// BaseHashes contains the receiver's last-known hashes. A changed receiver
	// file is rejected instead of silently overwritten when supplied.
	BaseHashes map[string]string
}

func BuildSyncManifest(root string, opt SyncOptions) (SyncManifest, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return SyncManifest{}, err
	}
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return SyncManifest{}, errors.New("sync root must be a directory")
	}
	out := SyncManifest{Root: root}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !syncMatch(rel, opt.Include, opt.Exclude) {
			if d.IsDir() && syncExcludedDir(rel, opt.Exclude) {
				return filepath.SkipDir
			}
			if d.IsDir() {
				return nil
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := SyncEntry{Path: rel, Size: info.Size(), Mode: uint32(info.Mode().Perm())}
		if d.Type()&os.ModeSymlink != 0 {
			if !opt.FollowSymlinks {
				entry.Symlink = true
				out.Entries = append(out.Entries, entry)
				return nil
			}
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if opt.MaxFileSize > 0 && info.Size() > opt.MaxFileSize {
			return errors.New("sync file exceeds maximum size")
		}
		entry.SHA256, err = digestPath(path)
		if err != nil {
			return err
		}
		out.Entries = append(out.Entries, entry)
		return nil
	})
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Path < out.Entries[j].Path })
	return out, err
}

func digestPath(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 256<<10)
	for {
		n, e := f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				break
			}
			return "", e
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func syncMatch(path string, include, exclude []string) bool {
	for _, p := range exclude {
		if ok, _ := filepath.Match(p, path); ok || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return false
		}
	}
	if len(include) == 0 {
		return true
	}
	for _, p := range include {
		if ok, _ := filepath.Match(p, path); ok || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

func syncExcludedDir(path string, exclude []string) bool {
	for _, pattern := range exclude {
		pattern = strings.TrimSuffix(pattern, "/")
		if pattern == path || strings.HasPrefix(path, pattern+"/") {
			return true
		}
	}
	return false
}

func SecureSyncPath(root, rel string) (string, error) {
	if rel == "" || strings.ContainsRune(rel, 0) || filepath.IsAbs(rel) {
		return "", errors.New("invalid sync path")
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("sync path escapes root")
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	out, err := filepath.Abs(filepath.Join(base, clean))
	if err != nil {
		return "", err
	}
	if out != base && !strings.HasPrefix(out, base+string(filepath.Separator)) {
		return "", errors.New("sync path escapes root")
	}
	return out, nil
}

// SecureSyncRoot resolves a remote sync directory. It accepts an empty or
// dot-relative path for the configured root while rejecting symlinked roots.
func SecureSyncRoot(root, rel string) (string, error) {
	if strings.ContainsRune(rel, 0) || filepath.IsAbs(rel) {
		return "", errors.New("invalid sync root")
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(base)
	if err != nil || !st.IsDir() {
		return "", errors.New("sync root must be a directory")
	}
	if strings.TrimSpace(rel) == "" || filepath.Clean(rel) == "." {
		return base, nil
	}
	out, err := SecureSyncPath(base, rel)
	if err != nil {
		return "", err
	}
	st, err = os.Stat(out)
	if err != nil || !st.IsDir() {
		return "", errors.New("sync root must be a directory")
	}
	return filepath.EvalSymlinks(out)
}

// SyncTrees applies a manifest-driven local tree sync. The same manifest and
// safe-path rules are used by the remote operation, so this is also the
// portable installer/Termux fallback when a resident peer is unavailable.
func SyncTrees(src, dst string, opt SyncOptions, deleteExtraneous bool) error {
	sm, err := BuildSyncManifest(src, opt)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, e := range sm.Entries {
		if e.Symlink {
			continue
		} // explicit no-follow policy
		target, err := SecureSyncPath(dst, e.Path)
		if err != nil {
			return err
		}
		seen[e.Path] = true
		info, statErr := os.Stat(target)
		if statErr == nil && !info.Mode().IsRegular() {
			return errors.New("sync destination is not a regular file")
		}
		if statErr == nil {
			got, _ := digestPath(target)
			if base, ok := opt.BaseHashes[e.Path]; ok && !strings.EqualFold(got, base) && !strings.EqualFold(got, e.SHA256) {
				return errors.New("sync conflict at " + e.Path)
			}
			if got == e.SHA256 {
				continue
			}
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		in, err := os.Open(filepath.Join(src, filepath.FromSlash(e.Path)))
		if err != nil {
			return err
		}
		part := target + ".arpl-part"
		out, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			in.Close()
			return err
		}
		start, _ := out.Seek(0, io.SeekEnd)
		if start > e.Size {
			out.Close()
			in.Close()
			_ = os.Remove(part)
			return errors.New("invalid sync resume part")
		}
		_, _ = in.Seek(start, io.SeekStart)
		_, err = io.Copy(out, in)
		_ = out.Close()
		_ = in.Close()
		if err != nil {
			return err
		}
		if got, _ := digestPath(part); got != e.SHA256 {
			return errors.New("sync checksum mismatch")
		}
		if err = os.Rename(part, target); err != nil {
			return err
		}
	}
	if deleteExtraneous {
		return filepath.Walk(dst, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.IsDir() {
				return walkErr
			}
			rel, _ := filepath.Rel(dst, path)
			if strings.HasSuffix(rel, ".arpl-part") {
				return nil
			}
			if !seen[filepath.ToSlash(rel)] {
				return os.Remove(path)
			}
			return nil
		})
	}
	return nil
}
