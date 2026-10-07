package snapshots

import (
	"bytes"
	"context"
	"sync"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/snapshots"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// Repository is an in-process test double for Repository.
type Repository struct {
	mu      sync.RWMutex
	history map[string][]snapshot.Envelope
}

func NewRepository() *Repository {
	return &Repository{history: make(map[string][]snapshot.Envelope)}
}

func cloneEnvelope(value snapshot.Envelope) snapshot.Envelope {
	value.Payload = bytes.Clone(value.Payload)
	value.Hash = bytes.Clone(value.Hash)
	value.Signature = bytes.Clone(value.Signature)

	return value
}

// RemoveRevision simulates a corrupted persisted history in service tests.
func (s *Repository) RemoveRevision(networkID string, revision uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	page := s.history[networkID]
	for index, envelope := range page {
		value, err := snapshot.Decode(envelope)
		if err == nil && value.Revision == revision {
			s.history[networkID] = append(page[:index:index], page[index+1:]...)
			return
		}
	}
}

func (s *Repository) Append(
	ctx context.Context,
	networkID string,
	expectedRevision uint64,
	expectedHash []byte,
	envelope snapshot.Envelope,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

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
		return domainpkg.ErrSnapshotConflict
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

func (s *Repository) Latest(ctx context.Context, networkID string) (snapshot.Envelope, error) {
	if err := ctx.Err(); err != nil {
		var zero snapshot.Envelope
		return zero, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	page := s.history[networkID]
	if len(page) == 0 {
		return snapshot.Envelope{}, domainpkg.ErrSnapshotUnavailable
	}

	return cloneEnvelope(page[len(page)-1]), nil
}

func (s *Repository) History(
	ctx context.Context,
	networkID string,
	afterRevision uint64,
	limit int,
) ([]snapshot.Envelope, error) {
	if err := ctx.Err(); err != nil {
		var zero []snapshot.Envelope
		return zero, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit < 1 || limit > domainpkg.MaxHistoryPageSize+1 {
		return nil, domainpkg.ErrHistoryCursor
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

var _ domainpkg.Repository = (*Repository)(nil)
