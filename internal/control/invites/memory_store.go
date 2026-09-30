package invites

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-process test double for Repository.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

func (s *MemoryStore) Save(_ context.Context, record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.records[record.InviteID]; exists {
		if current.Status == StatusBlocked {
			return ErrInviteBlocked
		}
		if SameSubmission(current, record) {
			return nil
		}
		return ErrInviteConsumed
	}
	s.records[record.InviteID] = record
	return nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, ErrInviteNotFound
	}
	return record, nil
}

func (s *MemoryStore) Approve(_ context.Context, id string, at time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, ErrInviteNotFound
	}
	if record.Status != StatusPending {
		return Record{}, ErrInviteConsumed
	}
	record.Status = StatusApproved
	record.ApprovedAt = &at
	s.records[id] = record
	return record, nil
}

func (s *MemoryStore) RecordInvalidCodeAttempt(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return ErrInviteNotFound
	}
	if record.Status == StatusBlocked {
		return ErrInviteBlocked
	}
	if record.Status != StatusPending {
		return ErrInviteConsumed
	}
	record.FailedCodeAttempts++
	if record.FailedCodeAttempts >= MaxInvalidCodeAttempts {
		record.Status = StatusBlocked
		record.BlockedAt = &at
		s.records[id] = record
		return ErrInviteBlocked
	}
	s.records[id] = record
	return nil
}

var _ Repository = (*MemoryStore)(nil)
