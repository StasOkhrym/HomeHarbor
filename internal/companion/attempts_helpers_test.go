package companion

import "sync"

type memoryInviteAttemptStore struct {
	mu       sync.Mutex
	attempts map[string]int
}

// newMemoryInviteAttemptStore is a test double; CLI use requires durable attempt state.
func newMemoryInviteAttemptStore() InviteAttemptStore {
	return &memoryInviteAttemptStore{attempts: make(map[string]int)}
}

func (s *memoryInviteAttemptStore) Check(inviteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.attempts[inviteID] >= MaxInviteCodeAttempts {
		return ErrInviteAttemptsLocked
	}

	return nil
}

func (s *memoryInviteAttemptStore) RecordFailure(inviteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.attempts[inviteID] >= MaxInviteCodeAttempts {
		return ErrInviteAttemptsLocked
	}

	s.attempts[inviteID]++
	if s.attempts[inviteID] >= MaxInviteCodeAttempts {
		return ErrInviteAttemptsLocked
	}

	return nil
}
