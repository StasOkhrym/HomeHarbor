package workflows

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
)

type MailStatus struct {
	Configured        bool                     `json:"configured"`
	Recipient         string                   `json:"recipient"`
	RecipientVerified bool                     `json:"recipient_verified"`
	Test              notifications.TestStatus `json:"test"`
}

// SMTPStatus reports configured capability and durable last-test bookkeeping.
// It does not dial SMTP or imply that the remote server is currently reachable.
func (s *AccountMail) SMTPStatus(
	ctx context.Context,
	principal identity.Principal,
) (MailStatus, error) {
	if !principal.CanManageAccounts() || principal.AccountID != identity.OwnerAccountID {
		return MailStatus{}, identity.ErrInvalidCredential
	}

	var state MailStatus

	err := s.within(ctx, func(ctx context.Context, tx AccountMailTransaction) error {
		account, err := tx.Accounts.OwnerForUpdate(
			ctx,
			identity.AccountScope{
				AccountID:   principal.AccountID,
				AuthVersion: principal.AuthVersion,
				Purpose:     principal.Purpose,
			},
		)
		if err != nil {
			return err
		}

		last, err := tx.Deliveries.LastSMTPTest(ctx, account.ID)
		if err != nil {
			return err
		}

		state = MailStatus{
			Configured:        s.codec != nil,
			Recipient:         account.Email,
			RecipientVerified: account.EmailVerifiedAt != nil,
			Test:              last,
		}

		return nil
	})
	if err != nil {
		return MailStatus{}, err
	}

	return state, nil
}

func (s *AccountMail) SendSMTPTest(ctx context.Context, principal identity.Principal) error {
	scope, _, err := s.recent(ctx, principal, true)
	if err != nil {
		return err
	}
	if s.codec == nil {
		return ErrMailDisabled
	}

	id, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		return identity.ErrSecurityStateUnavailable
	}

	return s.within(ctx, func(ctx context.Context, tx AccountMailTransaction) error {
		account, err := tx.Accounts.OwnerForUpdate(ctx, scope)
		if err != nil {
			return err
		}
		if account.EmailVerifiedAt == nil {
			return identity.ErrInvalidCredential
		}

		now := s.clock()
		prepared, err := s.codec.Prepare(notifications.Intent{
			ID: id.String(), AccountID: account.ID, Kind: notifications.SMTPTest, To: account.Email,
			CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		})
		if err != nil {
			return err
		}

		return tx.Deliveries.EnqueueSMTPTest(ctx, prepared)
	})
}
