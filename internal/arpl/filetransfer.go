package arpl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var ErrPathTraversal = errors.New("ARPL path is outside an allowed root")

// FileReceiver writes bounded, resumable .part files and atomically renames
// only after the declared SHA-256 digest and size are complete.
type FileReceiver struct {
	Roots       []string
	MaxFileSize int64
}
type Transfer struct {
	receiver     *FileReceiver
	final, part  string
	file         *os.File
	size, offset int64
	expected     [32]byte
	replace      bool
	mode         os.FileMode
	hash         hashState
}
type hashState struct {
	h   io.Writer
	sum func() [32]byte
}

func (r *FileReceiver) Begin(name string, size int64, sha256Hex string, offset int64) (*Transfer, error) {
	return r.BeginWithOptions(name, size, sha256Hex, offset, false)
}

func (r *FileReceiver) BeginWithOptions(name string, size int64, sha256Hex string, offset int64, replace bool) (*Transfer, error) {
	if r == nil || len(r.Roots) == 0 {
		return nil, errors.New("at least one ARPL allowed root is required")
	}
	if size < 0 || (r.MaxFileSize > 0 && size > r.MaxFileSize) {
		return nil, errors.New("ARPL file size is not allowed")
	}
	if len(sha256Hex) != 64 {
		return nil, errors.New("ARPL SHA-256 digest is required")
	}
	digest, err := hex.DecodeString(strings.ToLower(sha256Hex))
	if err != nil {
		return nil, errors.New("invalid ARPL SHA-256 digest")
	}
	var expected [32]byte
	copy(expected[:], digest)
	root, final, err := r.safePath(name)
	if err != nil {
		return nil, err
	}
	_ = root
	part := final + ".part"
	if err = rejectSymlink(final); err != nil {
		return nil, err
	}
	if err = rejectSymlink(part); err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, errors.New("invalid ARPL resume offset")
	}
	st, statErr := os.Stat(part)
	if statErr == nil {
		if !st.Mode().IsRegular() {
			return nil, errors.New("ARPL part path is not regular")
		}
		if offset == 0 {
			offset = st.Size()
		}
		if st.Size() != offset {
			return nil, fmt.Errorf("ARPL resume offset %d does not match part size %d", offset, st.Size())
		}
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	} else if offset != 0 {
		return nil, errors.New("ARPL resume offset has no part file")
	}
	if offset > size {
		return nil, errors.New("ARPL resume offset exceeds file size")
	}
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	if offset > 0 {
		prefix, err := os.Open(part)
		if err != nil {
			f.Close()
			return nil, err
		}
		_, err = io.CopyN(h, prefix, offset)
		prefix.Close()
		if err != nil {
			f.Close()
			return nil, err
		}
	}
	return &Transfer{receiver: r, final: final, part: part, file: f, size: size, offset: offset, expected: expected, replace: replace, hash: hashState{h: h, sum: func() [32]byte { var out [32]byte; copy(out[:], h.Sum(nil)); return out }}}, nil
}

func (t *Transfer) WriteChunk(offset int64, b []byte) error {
	if t == nil || t.file == nil {
		return errors.New("ARPL transfer is closed")
	}
	if offset != t.offset {
		return fmt.Errorf("ARPL chunk offset %d does not match %d", offset, t.offset)
	}
	if int64(len(b)) > t.size-t.offset {
		return errors.New("ARPL chunk exceeds declared file size")
	}
	if _, err := t.file.Write(b); err != nil {
		return err
	}
	_, _ = t.hash.h.Write(b)
	t.offset += int64(len(b))
	return nil
}
func (t *Transfer) Offset() int64 {
	if t == nil {
		return 0
	}
	return t.offset
}
func (t *Transfer) Complete() error {
	if t == nil || t.file == nil {
		return errors.New("ARPL transfer is closed")
	}
	if t.offset != t.size {
		return fmt.Errorf("ARPL transfer incomplete: %d/%d", t.offset, t.size)
	}
	if t.hash.sum() != t.expected {
		return errors.New("ARPL SHA-256 mismatch")
	}
	if err := t.file.Sync(); err != nil {
		t.file.Close()
		return err
	}
	if err := t.file.Close(); err != nil {
		return err
	}
	if t.mode != 0 {
		if err := os.Chmod(t.part, t.mode.Perm()); err != nil {
			return err
		}
	}
	if err := rejectSymlink(t.final); err != nil {
		return err
	}
	if _, err := os.Lstat(t.final); err == nil {
		if !t.replace {
			return errors.New("ARPL final path already exists")
		}
		if err := rejectSymlink(t.final); err != nil {
			return err
		}
		if err := os.Remove(t.final); err != nil {
			return err
		}
	}
	if err := os.Rename(t.part, t.final); err != nil {
		return err
	}
	t.file = nil
	return nil
}
func (t *Transfer) Abort() error {
	if t == nil || t.file == nil {
		return nil
	}
	err := t.file.Close()
	t.file = nil
	return err
}

func (r *FileReceiver) safePath(name string) (string, string, error) {
	if name == "" || filepath.IsAbs(name) || strings.ContainsRune(name, 0) {
		return "", "", ErrPathTraversal
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", "", ErrPathTraversal
	}
	for _, configured := range r.Roots {
		root, err := filepath.Abs(configured)
		if err != nil {
			continue
		}
		root, err = filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		candidate := filepath.Join(root, clean)
		probe := candidate
		for {
			resolved, resolveErr := filepath.EvalSymlinks(probe)
			if resolveErr == nil {
				if !withinPath(root, resolved) {
					return "", "", ErrPathTraversal
				}
				if probe != candidate {
					rel, relErr := filepath.Rel(probe, candidate)
					if relErr != nil {
						return "", "", ErrPathTraversal
					}
					candidate = filepath.Join(resolved, rel)
				} else {
					candidate = resolved
				}
				break
			}
			if !os.IsNotExist(resolveErr) || filepath.Dir(probe) == probe {
				candidate = ""
				break
			}
			probe = filepath.Dir(probe)
		}
		if candidate == "" {
			continue
		}
		if withinPath(root, candidate) {
			return root, candidate, nil
		}
	}
	return "", "", ErrPathTraversal
}
func withinPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func rejectSymlink(path string) error {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return ErrPathTraversal
	}
	return nil
}
