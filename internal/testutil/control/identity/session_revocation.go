package identity

import (
	"context"
	"math"

	domain "github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) RevokeSessions(ctx context.Context, scope domain.AccountScope) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.accounts[scope.AccountID]
	if scope.Purpose != domain.SessionAdmin || !scope.Allows(account) ||
		account.AuthVersion >= math.MaxInt64 {
		return domain.ErrInvalidCredential
	}

	account.AuthVersion++
	s.accounts[scope.AccountID] = account

	return nil
}
