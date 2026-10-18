package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"time"
)

type EnrollmentAccounts interface {
	AccountReader
	AccountByEmail(context.Context, string) (Account, error)
}
type EnrollmentFactors interface {
	BeginInvitedTOTP(context.Context, FactorContext) (TOTPEnrollment, error)
	ConfirmInvitedTOTP(context.Context, FactorContext, string) error
	BeginInvitedPasskey(context.Context, FactorContext, string) (BeginCeremony, error)
	FinishInvitedPasskey(context.Context, FactorContext, string, []byte) error
}

// EnrollmentService admits only password-proven, email-verified invitations.
// Its proof repository must have a separate namespace from normal login. It has
// no session issuer and never fabricates an administrative Principal.
type EnrollmentService struct {
	accounts  EnrollmentAccounts
	proofs    PreauthRepository
	passwords *PasswordHasher
	factors   EnrollmentFactors
	now       func() time.Time
	random    io.Reader
}

func NewEnrollmentService(
	accounts EnrollmentAccounts,
	proofs PreauthRepository,
	passwords *PasswordHasher,
	factors EnrollmentFactors,
	now func() time.Time,
	random io.Reader,
) (*EnrollmentService, error) {
	if accounts == nil || proofs == nil || passwords == nil || factors == nil {
		return nil, ErrSecurityStateUnavailable
	}

	if now == nil {
		now = time.Now
	}

	if random == nil {
		random = rand.Reader
	}

	return &EnrollmentService{
		accounts:  accounts,
		proofs:    proofs,
		passwords: passwords,
		factors:   factors,
		now:       now,
		random:    random,
	}, nil
}

func (s *EnrollmentService) Password(
	ctx context.Context,
	input, password string,
) (IssuedPreauth, error) {
	email, emailErr := CanonicalEmail(input)
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	var account Account

	err := ErrInvalidCredential
	if emailErr == nil {
		account, err = s.accounts.AccountByEmail(operation, email)
	}

	cancel()
	if err != nil && !errors.Is(err, ErrInvalidCredential) {
		return IssuedPreauth{}, ErrSecurityStateUnavailable
	}

	verifyErr := s.passwords.Verify(ctx, account.PasswordHash, password)
	if verifyErr != nil && !errors.Is(verifyErr, ErrInvalidCredential) {
		return IssuedPreauth{}, securityStoreError(verifyErr)
	}

	scope := AccountScope{
		AccountID:   account.ID,
		AuthVersion: account.AuthVersion,
		Purpose:     SessionEnrollment,
	}
	if err != nil || verifyErr != nil || account.Email != email || !scope.Allows(account) {
		return IssuedPreauth{}, ErrInvalidCredential
	}

	raw := make([]byte, 32)
	defer clear(raw)

	if _, err := io.ReadFull(s.random, raw); err != nil {
		return IssuedPreauth{}, ErrSecurityStateUnavailable
	}

	token := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now().UTC()
	record := Preauth{
		Hash:        hashToken(token),
		AccountID:   account.ID,
		AuthVersion: account.AuthVersion,
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}
	operation, cancel = context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := s.proofs.SavePreauth(operation, record); err != nil {
		return IssuedPreauth{}, securityStoreError(err)
	}

	return IssuedPreauth{Token: token, ExpiresAt: record.ExpiresAt}, nil
}

func (s *EnrollmentService) resolve(
	ctx context.Context,
	token string,
	attempt bool,
) (FactorContext, error) {
	if len(token) != 43 {
		return FactorContext{}, ErrInvalidCredential
	}

	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	defer clear(raw)

	if err != nil || len(raw) != 32 {
		return FactorContext{}, ErrInvalidCredential
	}

	hash := hashToken(token)
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var record Preauth
	if attempt {
		record, err = s.proofs.AttemptPreauth(operation, hash, s.now().UTC())
	} else {
		record, err = s.proofs.ReadPreauth(operation, hash, s.now().UTC())
	}

	if err != nil {
		return FactorContext{}, securityStoreError(err)
	}

	now := s.now().UTC()
	if record.Hash != hash || record.CreatedAt.IsZero() || now.Before(record.CreatedAt) ||
		!now.Before(record.ExpiresAt) ||
		!record.ExpiresAt.After(record.CreatedAt) ||
		record.ExpiresAt.Sub(record.CreatedAt) > 5*time.Minute ||
		record.Attempts < 0 ||
		record.Attempts > 5 ||
		(!attempt && record.Attempts >= 5) ||
		(attempt && record.Attempts < 1) {
		return FactorContext{}, ErrInvalidCredential
	}

	account, err := readAccount(operation, s.accounts, record.AccountID)
	if err != nil {
		return FactorContext{}, err
	}

	scope := AccountScope{
		AccountID:   record.AccountID,
		AuthVersion: record.AuthVersion,
		Purpose:     SessionEnrollment,
	}
	if !scope.Allows(account) {
		return FactorContext{}, ErrInvalidCredential
	}

	return FactorContext{AccountScope: scope, Binding: hash}, nil
}

func (s *EnrollmentService) Context(ctx context.Context, token string) (FactorContext, error) {
	return s.resolve(ctx, token, false)
}

func (s *EnrollmentService) BeginTOTP(ctx context.Context, token string) (TOTPEnrollment, error) {
	factor, err := s.Context(ctx, token)
	if err != nil {
		return TOTPEnrollment{}, err
	}

	return s.factors.BeginInvitedTOTP(ctx, factor)
}

func (s *EnrollmentService) BeginPasskey(
	ctx context.Context,
	token, name string,
) (BeginCeremony, error) {
	factor, err := s.Context(ctx, token)
	if err != nil {
		return BeginCeremony{}, err
	}

	return s.factors.BeginInvitedPasskey(ctx, factor, name)
}

func (s *EnrollmentService) complete(
	ctx context.Context,
	token string,
	finish func(FactorContext) error,
) error {
	factor, err := s.resolve(ctx, token, true)
	if err != nil {
		return err
	}

	if err := finish(factor); err != nil {
		return err
	}

	// Activation and epoch change already committed in SQL. A failed deletion
	// cannot resurrect this proof; retrying requires ordinary password+MFA login.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()

	if _, err := s.proofs.ConsumePreauth(cleanup, factor.Binding, s.now().UTC()); err != nil {
		slog.Warn("completed enrollment proof cleanup unavailable")
	}

	return nil
}

func (s *EnrollmentService) ConfirmTOTP(ctx context.Context, token, code string) error {
	return s.complete(
		ctx,
		token,
		func(factor FactorContext) error { return s.factors.ConfirmInvitedTOTP(ctx, factor, code) },
	)
}

func (s *EnrollmentService) FinishPasskey(
	ctx context.Context,
	token, id string,
	response []byte,
) error {
	return s.complete(
		ctx,
		token,
		func(factor FactorContext) error { return s.factors.FinishInvitedPasskey(ctx, factor, id, response) },
	)
}
