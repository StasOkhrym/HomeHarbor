// Package snapshots stores and validates the signed network state exchanged
// between the trusted companion and nodes. Control is a verifier and relay,
// never the authority that invents LAN access.
package snapshots

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

var ErrSnapshotUnavailable = errors.New("signed network snapshot unavailable")

type Store interface {
	Save(context.Context, snapshot.Envelope) error
	Latest(context.Context) (snapshot.Envelope, error)
}

type Service struct {
	store     Store
	root      ed25519.PublicKey
	networkID string
	mu        sync.Mutex
}

func NewService(store Store, root ed25519.PublicKey, networkID string) *Service {
	return &Service{store: store, root: append(ed25519.PublicKey(nil), root...), networkID: networkID}
}

func (s *Service) Publish(ctx context.Context, envelope snapshot.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.store.Latest(ctx)
	currentRevision := uint64(0)
	var currentHash []byte
	if err == nil {
		value, decodeErr := snapshot.Decode(current)
		if decodeErr != nil {
			return decodeErr
		}
		currentRevision = value.Revision
		currentHash = current.Hash
	} else if !errors.Is(err, ErrSnapshotUnavailable) {
		return err
	}
	if err := snapshot.VerifyNext(envelope, s.root, s.networkID, currentRevision, currentHash); err != nil {
		return err
	}
	return s.store.Save(ctx, envelope)
}

func (s *Service) Latest(ctx context.Context) (snapshot.Envelope, error) {
	return s.store.Latest(ctx)
}

type MemoryStore struct {
	mu      sync.RWMutex
	current *snapshot.Envelope
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func (s *MemoryStore) Save(_ context.Context, envelope snapshot.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := envelope
	copy.Payload = append([]byte(nil), envelope.Payload...)
	copy.Hash = append([]byte(nil), envelope.Hash...)
	copy.Signature = append([]byte(nil), envelope.Signature...)
	s.current = &copy
	return nil
}

func (s *MemoryStore) Latest(_ context.Context) (snapshot.Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return snapshot.Envelope{}, ErrSnapshotUnavailable
	}
	copy := *s.current
	copy.Payload = append([]byte(nil), s.current.Payload...)
	copy.Hash = append([]byte(nil), s.current.Hash...)
	copy.Signature = append([]byte(nil), s.current.Signature...)
	return copy, nil
}
