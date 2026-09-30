package snapshots

import (
	"bytes"
	"context"
	"sync"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

// MemoryStore is an in-process test double for Repository.
type MemoryStore struct {
	mu      sync.RWMutex
	history map[string][]snapshot.Envelope
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{history: make(map[string][]snapshot.Envelope)}
}

func cloneEnvelope(value snapshot.Envelope) snapshot.Envelope {
	value.Payload = bytes.Clone(value.Payload)
	value.Hash = bytes.Clone(value.Hash)
	value.Signature = bytes.Clone(value.Signature)

	return value
}

func (s *MemoryStore) Append(_ context.Context, networkID string, expectedRevision uint64, expectedHash []byte, envelope snapshot.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	page := s.history[networkID]
	var revision uint64
	var hash []byte
	if len(page) != 0 {
		value, err := snapshot.Decode(page[len(page)-1])
		if err != nil {
			return err
		}
		revision, hash = value.Revision, page[len(page)-1].Hash
	}
	if revision != expectedRevision || !bytes.Equal(hash, expectedHash) {
		return ErrSnapshotConflict
	}
	value, err := snapshot.Decode(envelope)
	if err != nil {
		return err
	}
	if value.NetworkID != networkID || value.Revision != revision+1 {
		return snapshot.ErrRevisionGap
	}
	if !bytes.Equal(value.PreviousHash, hash) {
		return snapshot.ErrPreviousHash
	}
	s.history[networkID] = append(page, cloneEnvelope(envelope))
	return nil
}

func (s *MemoryStore) Latest(_ context.Context, networkID string) (snapshot.Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	page := s.history[networkID]
	if len(page) == 0 {
		return snapshot.Envelope{}, ErrSnapshotUnavailable
	}
	return cloneEnvelope(page[len(page)-1]), nil
}

func (s *MemoryStore) History(_ context.Context, networkID string, afterRevision uint64, limit int) ([]snapshot.Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit < 1 || limit > MaxHistoryPageSize+1 {
		return nil, ErrHistoryCursor
	}
	result := []snapshot.Envelope{}
	for _, envelope := range s.history[networkID] {
		value, err := snapshot.Decode(envelope)
		if err != nil {
			return nil, err
		}
		if value.Revision > afterRevision {
			result = append(result, cloneEnvelope(envelope))
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

var _ Repository = (*MemoryStore)(nil)
