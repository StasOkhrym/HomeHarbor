package invites

import (
	"bytes"
	"context"
	"sync"
	"time"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/invites"
)

// Repository is an in-process test double for invites.Repository.
type Repository struct {
	mu      sync.Mutex
	records map[string]domainpkg.Record
}

func NewRepository() *Repository {
	return &Repository{records: make(map[string]domainpkg.Record)}
}

func (s *Repository) Save(ctx context.Context, record domainpkg.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if current, exists := s.records[record.InviteID]; exists {
		if current.Status == domainpkg.StatusBlocked {
			return domainpkg.ErrInviteBlocked
		}
		if domainpkg.SameSubmission(current, record) {
			return nil
		}

		return domainpkg.ErrInviteConsumed
	}

	s.records[record.InviteID] = cloneRecord(record)

	return nil
}

func (s *Repository) Get(ctx context.Context, id string) (domainpkg.Record, error) {
	if err := ctx.Err(); err != nil {
		var zero domainpkg.Record
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[id]
	if !ok {
		return domainpkg.Record{}, domainpkg.ErrInviteNotFound
	}

	return cloneRecord(record), nil
}

func (s *Repository) Approve(
	ctx context.Context,
	id string,
	at time.Time,
) (domainpkg.Record, error) {
	if err := ctx.Err(); err != nil {
		var zero domainpkg.Record
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[id]
	if !ok {
		return domainpkg.Record{}, domainpkg.ErrInviteNotFound
	}
	if record.Status != domainpkg.StatusPending {
		return domainpkg.Record{}, domainpkg.ErrInviteConsumed
	}

	record.Status = domainpkg.StatusApproved
	record.ApprovedAt = &at
	s.records[id] = record

	return cloneRecord(record), nil
}

func (s *Repository) RecordInvalidCodeAttempt(ctx context.Context, id string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[id]
	if !ok {
		return domainpkg.ErrInviteNotFound
	}
	if record.Status == domainpkg.StatusBlocked {
		return domainpkg.ErrInviteBlocked
	}
	if record.Status != domainpkg.StatusPending {
		return domainpkg.ErrInviteConsumed
	}

	record.FailedCodeAttempts++
	if record.FailedCodeAttempts >= domainpkg.MaxInvalidCodeAttempts {
		record.Status = domainpkg.StatusBlocked
		record.BlockedAt = &at
		s.records[id] = record

		return domainpkg.ErrInviteBlocked
	}

	s.records[id] = record

	return nil
}

var _ domainpkg.Repository = (*Repository)(nil)

func cloneRecord(record domainpkg.Record) domainpkg.Record {
	record.DevicePublic = bytes.Clone(record.DevicePublic)
	record.WireGuardPublicKey = bytes.Clone(record.WireGuardPublicKey)
	record.Permit.Payload = bytes.Clone(record.Permit.Payload)
	record.Permit.Signature = bytes.Clone(record.Permit.Signature)
	record.Proof.DevicePublicKey = bytes.Clone(record.Proof.DevicePublicKey)
	record.Proof.WireGuardPublicKey = bytes.Clone(record.Proof.WireGuardPublicKey)
	record.Proof.CodeDigest = bytes.Clone(record.Proof.CodeDigest)
	record.Proof.Signature = bytes.Clone(record.Proof.Signature)
	record.Proof.DeviceSignature = bytes.Clone(record.Proof.DeviceSignature)
	if record.ApprovedAt != nil {
		at := *record.ApprovedAt
		record.ApprovedAt = &at
	}

	if record.BlockedAt != nil {
		at := *record.BlockedAt
		record.BlockedAt = &at
	}

	return record
}
