package identity

import (
	"bytes"
	"context"
	"time"

	domain "github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) TOTP(ctx context.Context, id string) (domain.TOTPRecord, error) {
	if err := ctx.Err(); err != nil {
		return domain.TOTPRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.totp[id]
	if !ok {
		return domain.TOTPRecord{}, domain.ErrInvalidCredential
	}

	return cloneTOTP(record), nil
}

func (s *Repository) SavePendingTOTP(
	ctx context.Context,
	scope domain.AccountScope,
	record domain.TOTPRecord,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if scope.Purpose != domain.SessionAdmin || !scope.Allows(s.accounts[scope.AccountID]) ||
		record.AccountID != scope.AccountID ||
		record.EnrollmentVersion != scope.AuthVersion {
		return domain.ErrInvalidCredential
	}
	if current, exists := s.totp[scope.AccountID]; exists && current.ConfirmedAt != nil {
		return domain.ErrFactorExists
	}
	if s.totp == nil {
		s.totp = make(map[string]domain.TOTPRecord)
	}
	s.totp[scope.AccountID] = cloneTOTP(record)
	return nil
}

func (s *Repository) ConfirmTOTP(
	ctx context.Context,
	scope domain.AccountScope,
	id string,
	step int64,
	now time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if scope.Purpose != domain.SessionAdmin || !scope.Allows(s.accounts[scope.AccountID]) {
		return domain.ErrInvalidCredential
	}
	record, exists := s.totp[scope.AccountID]
	if !exists || record.ID != id || record.ConfirmedAt != nil ||
		record.EnrollmentVersion != scope.AuthVersion ||
		now.Before(record.CreatedAt) || !now.Before(record.ExpiresAt) ||
		step <= record.LastStep {
		return domain.ErrInvalidCredential
	}
	record.ConfirmedAt = &now
	record.ExpiresAt = time.Time{}
	record.LastStep = step
	s.totp[scope.AccountID] = cloneTOTP(record)
	account := s.accounts[scope.AccountID]
	account.AuthVersion++
	s.accounts[scope.AccountID] = account
	return nil
}

func (s *Repository) ConsumeTOTP(
	ctx context.Context,
	scope domain.AccountScope,
	id string,
	step int64,
	_ time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if scope.Purpose != domain.SessionAdmin || !scope.Allows(s.accounts[scope.AccountID]) {
		return domain.ErrInvalidCredential
	}

	record, exists := s.totp[scope.AccountID]
	if !exists || record.ID != id || record.ConfirmedAt == nil || step <= record.LastStep {
		return domain.ErrInvalidCredential
	}

	record.LastStep = step
	s.totp[scope.AccountID] = record

	return nil
}

func (s *Repository) RemoveTOTP(ctx context.Context, scope domain.AccountScope) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if scope.Purpose != domain.SessionAdmin || !scope.Allows(s.accounts[scope.AccountID]) {
		return domain.ErrInvalidCredential
	}

	record, exists := s.totp[scope.AccountID]
	if !exists || record.ConfirmedAt == nil {
		return domain.ErrInvalidCredential
	}

	account := s.accounts[scope.AccountID]
	if len(s.credentials[string(account.UserHandle)]) == 0 {
		return domain.ErrLastMFA
	}

	delete(s.totp, scope.AccountID)
	account.AuthVersion++
	s.accounts[scope.AccountID] = account

	return nil
}

func cloneTOTP(record domain.TOTPRecord) domain.TOTPRecord {
	record.Ciphertext = bytes.Clone(record.Ciphertext)
	if record.ConfirmedAt != nil {
		confirmed := *record.ConfirmedAt
		record.ConfirmedAt = &confirmed
	}

	return record
}
