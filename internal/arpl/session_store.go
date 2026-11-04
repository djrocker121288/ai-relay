package arpl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type FileSessionStore struct{ Path string }

func (s FileSessionStore) Load(context.Context) (SessionState, error) {
	if s.Path == "" {
		return SessionState{}, errors.New("session state path is required")
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SessionState{}, nil
		}
		return SessionState{}, err
	}
	if len(b) > 64<<10 {
		return SessionState{}, errors.New("ARPL session state is too large")
	}
	var state SessionState
	if err := json.Unmarshal(b, &state); err != nil || len(state.SessionID) != 32 {
		return SessionState{}, errors.New("invalid ARPL session state")
	}
	return state, nil
}

func (s FileSessionStore) Save(_ context.Context, state SessionState) error {
	if s.Path == "" || len(state.SessionID) != 32 {
		return errors.New("invalid ARPL session state path")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".arpl-session-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(b, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, s.Path)
}
