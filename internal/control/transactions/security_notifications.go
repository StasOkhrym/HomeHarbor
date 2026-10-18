package transactions

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	identitypg "github.com/StasOkhrym/homeharbor/internal/control/identity/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	notificationpg "github.com/StasOkhrym/homeharbor/internal/control/notifications/storage"
)

// NotifyingIdentity binds sensitive identity writes and their private security
// notices to one SQL commit. Reads and login counters use the ordinary adapter.
// Only the composition root chooses this cross-module transaction policy.
type NotifyingIdentity struct {
	*identitypg.Repository
	pool  *pgxpool.Pool
	codec *notifications.Codec
	now   func() time.Time
}

func NewIdentityWithNotifications(
	pool *pgxpool.Pool,
	codec *notifications.Codec,
	now func() time.Time,
) *NotifyingIdentity {
	if now == nil {
		now = time.Now
	}

	return &NotifyingIdentity{Repository: identitypg.New(pool), pool: pool, codec: codec, now: now}
}

func securityMutationError(err error) error {
	if err == nil || errors.Is(err, identity.ErrInvalidCredential) ||
		errors.Is(err, identity.ErrLastMFA) ||
		errors.Is(err, identity.ErrFactorExists) ||
		errors.Is(err, identity.ErrFactorLimit) {
		return err
	}

	return identity.ErrSecurityStateUnavailable
}

func (s *NotifyingIdentity) change(
	ctx context.Context,
	scope identity.AccountScope,
	mutate func(context.Context, *identitypg.Repository) error,
) error {
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if s.codec == nil {
		return securityMutationError(mutate(operation, s.Repository))
	}

	tx, err := s.pool.Begin(operation)
	if err != nil {
		return identity.ErrSecurityStateUnavailable
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()

		_ = tx.Rollback(cleanup)
	}()

	accounts := identitypg.Bind(tx)
	if err := mutate(operation, accounts); err != nil {
		return securityMutationError(err)
	}

	account, err := accounts.Account(operation, scope.AccountID)
	if err != nil {
		return identity.ErrSecurityStateUnavailable
	}

	deliveries := notificationpg.Bind(tx)
	if account.AuthVersion != scope.AuthVersion {
		// Epoch changes fence these proofs. Scrub queued obsolete links in the
		// same commit while preserving security notices and other accounts.
		for _, kind := range []notifications.Kind{notifications.AdminInvitation, notifications.EmailVerification, notifications.PasswordReset} {
			if err := deliveries.CancelPending(operation, account.ID, kind); err != nil {
				return identity.ErrSecurityStateUnavailable
			}
		}
	}

	if account.Status == identity.AccountActive && account.EmailVerifiedAt != nil {
		id, err := uuid.NewRandom()
		if err != nil {
			return identity.ErrSecurityStateUnavailable
		}

		now := s.now().UTC().Truncate(time.Microsecond)
		prepared, err := s.codec.Prepare(
			notifications.Intent{
				ID:        id.String(),
				AccountID: account.ID,
				Kind:      notifications.SecurityNotice,
				To:        account.Email,
				CreatedAt: now,
				ExpiresAt: now.Add(24 * time.Hour),
			},
		)
		if err != nil {
			return identity.ErrSecurityStateUnavailable
		}

		if err := deliveries.Enqueue(operation, prepared); err != nil {
			return identity.ErrSecurityStateUnavailable
		}
	}

	return securityMutationError(tx.Commit(operation))
}

func (s *NotifyingIdentity) ConfirmTOTP(
	ctx context.Context,
	scope identity.AccountScope,
	id string,
	step int64,
	now time.Time,
) error {
	return s.change(ctx, scope, func(ctx context.Context, store *identitypg.Repository) error {
		return store.ConfirmTOTP(ctx, scope, id, step, now)
	})
}

func (s *NotifyingIdentity) RemoveTOTP(ctx context.Context, scope identity.AccountScope) error {
	return s.change(
		ctx,
		scope,
		func(ctx context.Context, store *identitypg.Repository) error { return store.RemoveTOTP(ctx, scope) },
	)
}

func (s *NotifyingIdentity) SavePersonalCredential(
	ctx context.Context,
	scope identity.AccountScope,
	value identity.NamedCredential,
) error {
	return s.change(ctx, scope, func(ctx context.Context, store *identitypg.Repository) error {
		return store.SavePersonalCredential(ctx, scope, value)
	})
}

func (s *NotifyingIdentity) RemovePasskey(
	ctx context.Context,
	scope identity.AccountScope,
	id []byte,
) error {
	return s.change(ctx, scope, func(ctx context.Context, store *identitypg.Repository) error {
		return store.RemovePasskey(ctx, scope, id)
	})
}

func (s *NotifyingIdentity) SaveRecoveryCodes(
	ctx context.Context,
	scope identity.AccountScope,
	codes []identity.RecoveryCode,
) error {
	return s.change(ctx, scope, func(ctx context.Context, store *identitypg.Repository) error {
		return store.SaveRecoveryCodes(ctx, scope, codes)
	})
}

func (s *NotifyingIdentity) RevokeSessions(ctx context.Context, scope identity.AccountScope) error {
	return s.change(
		ctx,
		scope,
		func(ctx context.Context, store *identitypg.Repository) error { return store.RevokeSessions(ctx, scope) },
	)
}

var (
	_ identity.Repository        = (*NotifyingIdentity)(nil)
	_ identity.PasskeyRepository = (*NotifyingIdentity)(nil)
	_ identity.MFARepository     = (*NotifyingIdentity)(nil)
)
