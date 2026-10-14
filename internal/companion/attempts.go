package companion

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const MaxInviteCodeAttempts = 5

var (
	ErrInviteAttemptsLocked      = errors.New("invite is locked after invalid code attempts")
	ErrInviteAttemptsUnavailable = errors.New("invite attempt state is not configured")
)

// InviteAttemptStore persists only a counter keyed by the opaque invite ID.
// It deliberately has no code, digest, permit, or device material, keeping
// the separate-channel secret local to the operator's companion.
type InviteAttemptStore interface {
	Check(string) error
	RecordFailure(string) error
}

type fileInviteAttemptState struct {
	Attempts map[string]int `json:"attempts"`
}

// FileInviteAttemptStore is the CLI-safe durable implementation. Its atomic
// replacement means a power loss cannot turn a recorded failed attempt into a
// successful retry, and the file mode keeps the local operational metadata
// private even though it contains no code material.
type FileInviteAttemptStore struct {
	mu   sync.Mutex
	path string
}

func NewFileInviteAttemptStore(path string) (*FileInviteAttemptStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrInviteAttemptsUnavailable
	}

	return &FileInviteAttemptStore{path: path}, nil
}

func (s *FileInviteAttemptStore) Check(inviteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.load()
	if err != nil {
		return err
	}
	if state.Attempts[inviteID] >= MaxInviteCodeAttempts {
		return ErrInviteAttemptsLocked
	}

	return nil
}

func (s *FileInviteAttemptStore) RecordFailure(inviteID string) error {
	if strings.TrimSpace(inviteID) == "" {
		return errors.New("invite ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.load()
	if err != nil {
		return err
	}
	if state.Attempts[inviteID] >= MaxInviteCodeAttempts {
		return ErrInviteAttemptsLocked
	}

	state.Attempts[inviteID]++

	if err := s.save(state); err != nil {
		return err
	}

	if state.Attempts[inviteID] >= MaxInviteCodeAttempts {
		return ErrInviteAttemptsLocked
	}

	return nil
}

func (s *FileInviteAttemptStore) load() (fileInviteAttemptState, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return fileInviteAttemptState{Attempts: make(map[string]int)}, nil
	}
	if err != nil {
		return fileInviteAttemptState{}, err
	}
	if len(data) > 1<<20 {
		return fileInviteAttemptState{}, errors.New("invite attempt state is too large")
	}

	var state fileInviteAttemptState

	if err := json.Unmarshal(data, &state); err != nil {
		return fileInviteAttemptState{}, fmt.Errorf("decode invite attempt state: %w", err)
	}

	if state.Attempts == nil {
		state.Attempts = make(map[string]int)
	}

	return state, nil
}

func (s *FileInviteAttemptStore) save(state fileInviteAttemptState) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".invite-attempts-*")
	if err != nil {
		return err
	}

	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}

	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}

	if err := temporary.Close(); err != nil {
		return err
	}

	return os.Rename(temporaryPath, s.path)
}
