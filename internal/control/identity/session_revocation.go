package identity

import (
	"context"
	"time"
)

// RevokeSessions requires the recent admitted account, never a target supplied
// by a client. Advancing its durable epoch fences every replica's old sessions
// and pending authentication proofs while preserving password and MFA material.
func (s *MFAService) RevokeSessions(ctx context.Context, principal Principal) error {
	scope, _, err := s.recentScope(ctx, principal)
	if err != nil {
		return err
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return mfaStoreError(s.store.RevokeSessions(operation, scope))
}
