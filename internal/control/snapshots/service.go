// Package snapshots stores and validates the signed network state exchanged
// between the trusted companion and nodes. Control is a verifier and relay,
// never the authority that invents LAN access.
package snapshots

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

var (
	ErrSnapshotUnavailable = errors.New("signed network snapshot unavailable")
	ErrSnapshotConflict    = errors.New("snapshot head changed before append")
	ErrHistoryCursor       = errors.New("invalid snapshot history cursor or limit")
)

const MaxHistoryPageSize = 16

type Repository interface {
	Append(context.Context, string, uint64, []byte, snapshot.Envelope) error
	Latest(context.Context, string) (snapshot.Envelope, error)
	History(context.Context, string, uint64, int) ([]snapshot.Envelope, error)
}

type Service struct {
	store     Repository
	root      ed25519.PublicKey
	networkID string
}

func NewService(store Repository, root ed25519.PublicKey, networkID string) *Service {
	return &Service{
		store:     store,
		root:      append(ed25519.PublicKey(nil), root...),
		networkID: networkID,
	}
}

func (s *Service) Publish(ctx context.Context, envelope snapshot.Envelope) error {
	current, err := s.store.Latest(ctx, s.networkID)
	currentRevision := uint64(0)
	var currentHash []byte
	if err == nil {
		value, decodeErr := snapshot.Verify(current, s.root, s.networkID)
		if decodeErr != nil {
			return decodeErr
		}

		currentRevision = value.Revision
		currentHash = current.Hash
	} else if !errors.Is(err, ErrSnapshotUnavailable) {
		return err
	}

	if err := snapshot.VerifyNext(
		envelope,
		s.root,
		s.networkID,
		currentRevision,
		currentHash,
	); err != nil {
		return err
	}

	return s.store.Append(ctx, s.networkID, currentRevision, currentHash, envelope)
}

func (s *Service) Latest(ctx context.Context) (snapshot.Envelope, error) {
	envelope, err := s.store.Latest(ctx, s.networkID)
	if err != nil {
		return snapshot.Envelope{}, err
	}

	if _, err := snapshot.Verify(envelope, s.root, s.networkID); err != nil {
		return snapshot.Envelope{}, err
	}

	return envelope, nil
}

// History verifies an ordered page against its persisted predecessor. Nodes
// still verify every envelope themselves against their own trusted cursor.
func (s *Service) History(
	ctx context.Context,
	afterRevision uint64,
	limit int,
) ([]snapshot.Envelope, error) {
	if limit < 1 || limit > MaxHistoryPageSize {
		return nil, ErrHistoryCursor
	}

	start, count := afterRevision, limit
	if afterRevision > 0 {
		start--
		count++
	}

	page, err := s.store.History(ctx, s.networkID, start, count)
	if err != nil {
		return nil, err
	}

	var hash []byte
	if afterRevision > 0 {
		if len(page) == 0 {
			return nil, ErrHistoryCursor
		}

		value, err := snapshot.Verify(page[0], s.root, s.networkID)
		if err != nil {
			return nil, err
		}
		if value.Revision != afterRevision {
			return nil, snapshot.ErrRevisionGap
		}

		hash = page[0].Hash
		page = page[1:]
	}

	if len(page) > limit {
		return nil, ErrHistoryCursor
	}

	for _, envelope := range page {
		if err := snapshot.VerifyNext(
			envelope,
			s.root,
			s.networkID,
			afterRevision,
			hash,
		); err != nil {
			return nil, err
		}

		afterRevision++
		hash = envelope.Hash
	}

	if page == nil {
		page = []snapshot.Envelope{}
	}

	return page, nil
}
