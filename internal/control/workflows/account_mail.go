package workflows

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
)

var ErrMailDisabled = errors.New("email delivery is not configured")

type MailAccountReader interface {
	identity.AccountReader
	AccountByEmail(context.Context, string) (identity.Account, error)
}
type MailAccountTransaction interface {
	OwnerForUpdate(context.Context, identity.AccountScope) (identity.Account, error)
	identity.AccountReader
	PrepareAdminInvitation(context.Context, identity.AccountScope, identity.Account) error
	SaveMailToken(context.Context, identity.MailToken) error
	ConsumeMailToken(context.Context, identity.MailTokenUse) (identity.Account, error)
	RevokeAdmin(context.Context, identity.AccountScope, string) error
}
type AccountMailDelivery interface {
	EnqueueSMTPTest(context.Context, notifications.Prepared) error
	LastSMTPTest(context.Context, string) (notifications.TestStatus, error)
	Enqueue(context.Context, notifications.Prepared) error
	CancelPending(context.Context, string, notifications.Kind) error
}
type AccountMailTransaction struct {
	Accounts   MailAccountTransaction
	Deliveries AccountMailDelivery
}
type AccountMailUnitOfWork interface {
	WithinAccountMail(context.Context, func(AccountMailTransaction) error) error
}

// AccountMail coordinates account mutations and private delivery atomically.
// No SMTP/network call runs inside this transaction or grants admin authority.
type AccountMail struct {
	uow       AccountMailUnitOfWork
	accounts  MailAccountReader
	passwords *identity.PasswordHasher
	codec     *notifications.Codec
	now       func() time.Time
	random    io.Reader
}

func NewAccountMail(
	uow AccountMailUnitOfWork,
	accounts MailAccountReader,
	passwords *identity.PasswordHasher,
	codec *notifications.Codec,
	now func() time.Time,
	random io.Reader,
) (*AccountMail, error) {
	if uow == nil || accounts == nil || passwords == nil {
		return nil, identity.ErrSecurityStateUnavailable
	}

	if now == nil {
		now = time.Now
	}

	if random == nil {
		random = rand.Reader
	}

	return &AccountMail{
		uow:       uow,
		accounts:  accounts,
		passwords: passwords,
		codec:     codec,
		now:       now,
		random:    random,
	}, nil
}
func (s *AccountMail) clock() time.Time { return s.now().UTC().Truncate(time.Microsecond) }
func mailStateError(err error) error {
	if errors.Is(err, notifications.ErrRateLimited) {
		return identity.ErrMailRateLimited
	}
	if err == nil || errors.Is(err, identity.ErrInvalidCredential) ||
		errors.Is(err, identity.ErrInvitationConflict) ||
		errors.Is(err, identity.ErrMailRateLimited) ||
		errors.Is(err, identity.ErrRecentAuthentication) ||
		errors.Is(err, ErrMailDisabled) {
		return err
	}

	return identity.ErrSecurityStateUnavailable
}

func (s *AccountMail) within(
	ctx context.Context,
	fn func(context.Context, AccountMailTransaction) error,
) error {
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return mailStateError(
		s.uow.WithinAccountMail(
			operation,
			func(tx AccountMailTransaction) error { return fn(operation, tx) },
		),
	)
}

func (s *AccountMail) recent(
	ctx context.Context,
	principal identity.Principal,
	ownerOnly bool,
) (identity.AccountScope, identity.Account, error) {
	if !principal.CanManageNetwork() || (ownerOnly && !principal.CanManageAccounts()) {
		return identity.AccountScope{}, identity.Account{}, identity.ErrInvalidCredential
	}

	now := s.now().UTC()
	if principal.AuthenticatedAt.IsZero() || now.Before(principal.AuthenticatedAt) {
		return identity.AccountScope{}, identity.Account{}, identity.ErrInvalidCredential
	}
	if now.Sub(principal.AuthenticatedAt) >= 5*time.Minute {
		return identity.AccountScope{}, identity.Account{}, identity.ErrRecentAuthentication
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	account, err := s.accounts.Account(operation, principal.AccountID)
	if err != nil {
		return identity.AccountScope{}, identity.Account{}, mailStateError(err)
	}
	if principal.Role != account.Role {
		return identity.AccountScope{}, identity.Account{}, identity.ErrInvalidCredential
	}

	if _, err := account.Principal(
		identity.Session{
			AccountID:   principal.AccountID,
			AuthVersion: principal.AuthVersion,
			Purpose:     principal.Purpose,
			Method:      principal.Method,
			CreatedAt:   principal.AuthenticatedAt,
			ExpiresAt:   principal.AuthenticatedAt.Add(time.Minute),
		},
	); err != nil {
		return identity.AccountScope{}, identity.Account{}, err
	}

	return identity.AccountScope{
		AccountID:   account.ID,
		AuthVersion: account.AuthVersion,
		Purpose:     identity.SessionAdmin,
	}, account, nil
}

func (s *AccountMail) prepareToken(
	account identity.Account,
	purpose identity.MailPurpose,
) (identity.MailToken, notifications.Prepared, error) {
	if s.codec == nil {
		return identity.MailToken{}, notifications.Prepared{}, ErrMailDisabled
	}

	raw := make([]byte, 32)
	defer clear(raw)

	if _, err := io.ReadFull(s.random, raw); err != nil {
		return identity.MailToken{}, notifications.Prepared{}, identity.ErrSecurityStateUnavailable
	}

	value := base64.RawURLEncoding.EncodeToString(raw)

	id, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		return identity.MailToken{}, notifications.Prepared{}, identity.ErrSecurityStateUnavailable
	}

	now := s.clock()
	ttl := 24 * time.Hour
	if purpose == identity.MailPasswordReset {
		ttl = 15 * time.Minute
	}

	token := identity.MailToken{
		Hash:        sha256.Sum256([]byte(value)),
		AccountID:   account.ID,
		Email:       account.Email,
		AuthVersion: account.AuthVersion,
		Purpose:     purpose,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
	if !token.Valid() {
		return identity.MailToken{}, notifications.Prepared{}, identity.ErrInvalidCredential
	}

	prepared, err := s.codec.Prepare(
		notifications.Intent{
			ID:        id.String(),
			AccountID: account.ID,
			Kind:      notifications.Kind(purpose),
			To:        account.Email,
			Token:     value,
			CreatedAt: now,
			ExpiresAt: token.ExpiresAt,
		},
	)
	if err != nil {
		return identity.MailToken{}, notifications.Prepared{}, identity.ErrSecurityStateUnavailable
	}

	return token, prepared, nil
}

func (s *AccountMail) issue(
	ctx context.Context,
	tx AccountMailTransaction,
	token identity.MailToken,
	prepared notifications.Prepared,
) error {
	if err := tx.Accounts.SaveMailToken(ctx, token); err != nil {
		return err
	}

	if err := tx.Deliveries.CancelPending(ctx, token.AccountID, prepared.Kind); err != nil {
		return err
	}

	return tx.Deliveries.Enqueue(ctx, prepared)
}

// RequestPasswordReset intentionally gives unknown, unverified, malformed and
// recently requested accounts the same result. HTTP supplies source quotas.
func (s *AccountMail) RequestPasswordReset(ctx context.Context, input string) error {
	if s.codec == nil {
		return ErrMailDisabled
	}

	email, err := identity.CanonicalEmail(input)
	if err != nil {
		return nil
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	account, err := s.accounts.AccountByEmail(operation, email)
	cancel()
	if errors.Is(err, identity.ErrInvalidCredential) {
		return nil
	}
	if err != nil {
		return mailStateError(err)
	}
	if account.Status != identity.AccountActive || account.EmailVerifiedAt == nil {
		return nil
	}

	token, prepared, err := s.prepareToken(account, identity.MailPasswordReset)
	if err != nil {
		return mailStateError(err)
	}

	err = s.within(
		ctx,
		func(ctx context.Context, tx AccountMailTransaction) error { return s.issue(ctx, tx, token, prepared) },
	)
	if errors.Is(err, identity.ErrInvalidCredential) ||
		errors.Is(err, identity.ErrMailRateLimited) {
		return nil
	}

	return err
}

func (s *AccountMail) RequestEmailVerification(
	ctx context.Context,
	principal identity.Principal,
) error {
	_, account, err := s.recent(ctx, principal, false)
	if err != nil {
		return err
	}
	if account.EmailVerifiedAt != nil {
		return nil
	}

	token, prepared, err := s.prepareToken(account, identity.MailEmailVerification)
	if err != nil {
		return err
	}

	return s.within(
		ctx,
		func(ctx context.Context, tx AccountMailTransaction) error { return s.issue(ctx, tx, token, prepared) },
	)
}

func (s *AccountMail) InviteAdmin(
	ctx context.Context,
	principal identity.Principal,
	input string,
) (identity.AccountSubject, error) {
	owner, _, err := s.recent(ctx, principal, true)
	if err != nil {
		return identity.AccountSubject{}, err
	}
	if s.codec == nil {
		return identity.AccountSubject{}, ErrMailDisabled
	}

	email, err := identity.CanonicalEmail(input)
	if err != nil {
		return identity.AccountSubject{}, err
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	candidate, err := s.accounts.AccountByEmail(operation, email)
	cancel()
	switch {
	case errors.Is(err, identity.ErrInvalidCredential):
		id, err := uuid.NewRandomFromReader(s.random)
		if err != nil {
			return identity.AccountSubject{}, identity.ErrSecurityStateUnavailable
		}

		handle := make([]byte, 32)
		if _, err := io.ReadFull(s.random, handle); err != nil {
			return identity.AccountSubject{}, identity.ErrSecurityStateUnavailable
		}

		candidate = identity.Account{
			ID:          id.String(),
			Email:       email,
			Role:        identity.RoleAdmin,
			Status:      identity.AccountInvited,
			AuthVersion: 1,
			UserHandle:  handle,
			CreatedAt:   s.clock(),
		}
	case err != nil:
		return identity.AccountSubject{}, mailStateError(err)
	default:
		if candidate.Role != identity.RoleAdmin || candidate.Status != identity.AccountInvited {
			return identity.AccountSubject{}, identity.ErrInvitationConflict
		}

		candidate.AuthVersion++
		candidate.PasswordHash = ""
		candidate.EmailVerifiedAt = nil
	}

	token, prepared, err := s.prepareToken(candidate, identity.MailAdminInvitation)
	if err != nil {
		return identity.AccountSubject{}, err
	}

	err = s.within(ctx, func(ctx context.Context, tx AccountMailTransaction) error {
		if err := tx.Accounts.PrepareAdminInvitation(ctx, owner, candidate); err != nil {
			return err
		}

		return s.issue(ctx, tx, token, prepared)
	})
	if err != nil {
		return identity.AccountSubject{}, err
	}

	return candidate.Subject(), nil
}

func parseMailToken(token string) ([32]byte, error) {
	if len(token) != 43 {
		return [32]byte{}, identity.ErrInvalidCredential
	}

	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	defer clear(raw)

	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return [32]byte{}, identity.ErrInvalidCredential
	}

	return sha256.Sum256([]byte(token)), nil
}

func (s *AccountMail) consume(
	ctx context.Context,
	token string,
	purpose identity.MailPurpose,
	password string,
) (identity.AccountSubject, error) {
	hash, err := parseMailToken(token)
	if err != nil {
		return identity.AccountSubject{}, err
	}

	passwordHash := ""
	if purpose != identity.MailEmailVerification {
		if err := identity.ValidateNewPassword(password); err != nil {
			return identity.AccountSubject{}, identity.ErrInvalidCredential
		}

		passwordHash, err = s.passwords.Hash(ctx, password)
		if err != nil {
			return identity.AccountSubject{}, mailStateError(err)
		}
	}

	var subject identity.AccountSubject

	err = s.within(ctx, func(ctx context.Context, tx AccountMailTransaction) error {
		account, err := tx.Accounts.ConsumeMailToken(
			ctx,
			identity.MailTokenUse{
				Hash:         hash,
				Purpose:      purpose,
				Now:          s.clock(),
				PasswordHash: passwordHash,
			},
		)
		if err != nil {
			return err
		}

		subject = account.Subject()
		kind := notifications.Kind("")
		if purpose == identity.MailEmailVerification {
			kind = notifications.EmailVerification
		}

		if err := tx.Deliveries.CancelPending(ctx, account.ID, kind); err != nil {
			return err
		}

		if purpose == identity.MailEmailVerification {
			return nil
		}

		return s.notice(ctx, tx, account)
	})
	if err != nil {
		return identity.AccountSubject{}, err
	}

	return subject, nil
}

func (s *AccountMail) ResetPassword(
	ctx context.Context,
	token, password string,
) (identity.AccountSubject, error) {
	return s.consume(ctx, token, identity.MailPasswordReset, password)
}

func (s *AccountMail) AcceptInvitation(
	ctx context.Context,
	token, password string,
) (identity.AccountSubject, error) {
	return s.consume(ctx, token, identity.MailAdminInvitation, password)
}

func (s *AccountMail) VerifyEmail(
	ctx context.Context,
	token string,
) (identity.AccountSubject, error) {
	return s.consume(ctx, token, identity.MailEmailVerification, "")
}

func (s *AccountMail) notice(
	ctx context.Context,
	tx AccountMailTransaction,
	account identity.Account,
) error {
	if s.codec == nil || account.EmailVerifiedAt == nil {
		return nil
	}

	id, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		return identity.ErrSecurityStateUnavailable
	}

	now := s.clock()
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
		return err
	}

	return tx.Deliveries.Enqueue(ctx, prepared)
}

func (s *AccountMail) RevokeAdmin(
	ctx context.Context,
	principal identity.Principal,
	accountID string,
) (identity.AccountSubject, error) {
	owner, _, err := s.recent(ctx, principal, true)
	if err != nil {
		return identity.AccountSubject{}, err
	}

	var subject identity.AccountSubject

	err = s.within(ctx, func(ctx context.Context, tx AccountMailTransaction) error {
		if err := tx.Accounts.RevokeAdmin(ctx, owner, accountID); err != nil {
			return err
		}

		account, err := tx.Accounts.Account(ctx, accountID)
		if err != nil {
			return err
		}

		subject = account.Subject()

		return tx.Deliveries.CancelPending(ctx, accountID, "")
	})
	if err != nil {
		return identity.AccountSubject{}, err
	}

	return subject, nil
}
