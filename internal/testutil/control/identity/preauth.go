package identity

import (
	"context"
	"time"

	domain "github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) AccountByEmail(ctx context.Context, email string) (domain.Account, error) {
	if err := ctx.Err(); err != nil {
		return domain.Account{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, account := range s.accounts {
		if account.Email == email {
			return cloneAccount(account), nil
		}
	}

	return domain.Account{}, domain.ErrInvalidCredential
}

func (s *Repository) SavePreauth(ctx context.Context, record domain.Preauth) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.preauth == nil {
		s.preauth = make(map[[32]byte]domain.Preauth)
	}

	if _, exists := s.preauth[record.Hash]; exists {
		return domain.ErrInvalidCredential
	}

	s.preauth[record.Hash] = record

	return nil
}

func (s *Repository) AttemptPreauth(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (domain.Preauth, error) {
	if err := ctx.Err(); err != nil {
		return domain.Preauth{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.preauth[hash]
	if !ok || !now.Before(record.ExpiresAt) || record.Attempts >= 5 {
		return domain.Preauth{}, domain.ErrInvalidCredential
	}

	record.Attempts++
	s.preauth[hash] = record

	return record, nil
}

func (s *Repository) ConsumePreauth(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (domain.Preauth, error) {
	if err := ctx.Err(); err != nil {
		return domain.Preauth{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.preauth[hash]
	if !ok || !now.Before(record.ExpiresAt) || record.Attempts < 1 || record.Attempts > 5 {
		return domain.Preauth{}, domain.ErrInvalidCredential
	}

	delete(s.preauth, hash)
	return record, nil
}

func (s *Repository) ConfigureOwner(
	ctx context.Context,
	scope domain.AccountScope,
	email, hash string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.accounts[scope.AccountID]
	if scope.Purpose != domain.SessionMigration || !scope.Allows(account) {
		return domain.ErrInvalidCredential
	}

	for _, other := range s.accounts {
		if other.ID != account.ID && other.Email == email {
			return domain.ErrInvalidCredential
		}
	}

	account.Email = email
	account.PasswordHash = hash
	account.Status = domain.AccountActive
	account.AuthVersion++
	s.accounts[account.ID] = account

	return nil
}
