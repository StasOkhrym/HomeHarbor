package identity

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/platform/sealed"
)

var (
	ErrLastMFA              = errors.New("at least one active second factor is required")
	ErrFactorExists         = errors.New("second factor is already configured")
	ErrRecentAuthentication = errors.New("recent authentication required")
)

type (
	MFAConfig  struct{ EncryptionKey []byte }
	TOTPRecord struct {
		ID                string
		AccountID         string
		EnrollmentVersion uint64
		Ciphertext        []byte `json:"-"`
		CreatedAt         time.Time
		ExpiresAt         time.Time
		ConfirmedAt       *time.Time
		LastStep          int64
	}
)

type TOTPEnrollment struct {
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	ExpiresAt time.Time `json:"expires_at"`
}
type MFARepository interface {
	AccountReader
	TOTP(context.Context, string) (TOTPRecord, error)
	SavePendingTOTP(context.Context, AccountScope, TOTPRecord) error
	ConfirmTOTP(context.Context, AccountScope, string, int64, time.Time) error
	ConsumeTOTP(context.Context, AccountScope, string, int64, time.Time) error
	RemoveTOTP(context.Context, AccountScope) error
	FactorState(context.Context, AccountScope) (FactorState, error)
	RemovePasskey(context.Context, AccountScope, []byte) error
}
type MFAService struct {
	store    MFARepository
	passkeys *PasskeyService
	recovery *Service
	seeds    *sealed.Box
	now      func() time.Time
	random   io.Reader
}

func NewMFAService(
	config MFAConfig,
	store MFARepository,
	passkeys *PasskeyService,
	recovery *Service,
	now func() time.Time,
	random io.Reader,
) (*MFAService, error) {
	if store == nil || passkeys == nil || recovery == nil {
		return nil, errors.New("MFA account, passkey and recovery authorities are required")
	}

	box, err := sealed.New(config.EncryptionKey, "identity.totp")
	if err != nil {
		return nil, err
	}

	if now == nil {
		now = time.Now
	}

	if random == nil {
		random = rand.Reader
	}

	return &MFAService{
		store:    store,
		passkeys: passkeys,
		recovery: recovery,
		seeds:    box,
		now:      now,
		random:   random,
	}, nil
}

func (s *MFAService) currentScope(
	ctx context.Context,
	principal Principal,
) (AccountScope, Account, error) {
	account, err := readAccount(ctx, s.store, principal.AccountID)
	if err != nil {
		return AccountScope{}, Account{}, err
	}
	if principal.Purpose != SessionAdmin || principal.Role != account.Role {
		return AccountScope{}, Account{}, ErrInvalidCredential
	}

	proof := Session{
		AccountID:   principal.AccountID,
		AuthVersion: principal.AuthVersion,
		Purpose:     principal.Purpose,
		Method:      principal.Method,
		CreatedAt:   principal.AuthenticatedAt,
		ExpiresAt:   principal.AuthenticatedAt.Add(time.Minute),
	}
	if _, err := account.Principal(proof); err != nil {
		return AccountScope{}, Account{}, err
	}

	if s.now().UTC().Before(principal.AuthenticatedAt) {
		return AccountScope{}, Account{}, ErrInvalidCredential
	}

	return AccountScope{
		AccountID:   principal.AccountID,
		AuthVersion: principal.AuthVersion,
		Purpose:     SessionAdmin,
	}, account, nil
}

func (s *MFAService) recentScope(
	ctx context.Context,
	principal Principal,
) (AccountScope, Account, error) {
	scope, account, err := s.currentScope(ctx, principal)
	if err != nil {
		return AccountScope{}, Account{}, err
	}
	if s.now().UTC().Sub(principal.AuthenticatedAt) >= 5*time.Minute {
		return AccountScope{}, Account{}, ErrRecentAuthentication
	}

	return scope, account, nil
}

func (s *MFAService) BeginTOTP(ctx context.Context, principal Principal) (TOTPEnrollment, error) {
	scope, account, err := s.recentScope(ctx, principal)
	if err != nil {
		return TOTPEnrollment{}, err
	}

	return s.beginTOTP(ctx, scope, account)
}

func (s *MFAService) beginTOTP(
	ctx context.Context,
	scope AccountScope,
	account Account,
) (TOTPEnrollment, error) {
	seed := make([]byte, 20)
	if _, err := io.ReadFull(s.random, seed); err != nil {
		return TOTPEnrollment{}, ErrSecurityStateUnavailable
	}
	defer clear(seed)

	id, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		return TOTPEnrollment{}, ErrSecurityStateUnavailable
	}

	ciphertext, err := s.seeds.Seal(scope.AccountID, seed)
	if err != nil {
		return TOTPEnrollment{}, ErrSecurityStateUnavailable
	}

	now := s.now().UTC()
	record := TOTPRecord{
		ID:                id.String(),
		AccountID:         scope.AccountID,
		EnrollmentVersion: scope.AuthVersion,
		Ciphertext:        ciphertext,
		CreatedAt:         now,
		ExpiresAt:         now.Add(10 * time.Minute),
		LastStep:          -1,
	}
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := s.store.SavePendingTOTP(operation, scope, record); err != nil {
		return TOTPEnrollment{}, mfaStoreError(err)
	}

	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	uri := url.URL{Scheme: "otpauth", Host: "totp", Path: "HomeHarbor:" + account.Email}
	query := url.Values{
		"secret":    {secret},
		"issuer":    {"HomeHarbor"},
		"algorithm": {"SHA1"},
		"digits":    {"6"},
		"period":    {"30"},
	}
	uri.RawQuery = query.Encode()

	return TOTPEnrollment{Secret: secret, URI: uri.String(), ExpiresAt: record.ExpiresAt}, nil
}

func (s *MFAService) readTOTP(ctx context.Context, scope AccountScope) (TOTPRecord, []byte, error) {
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	record, err := s.store.TOTP(operation, scope.AccountID)
	if err != nil {
		return TOTPRecord{}, nil, mfaStoreError(err)
	}
	if record.AccountID != scope.AccountID || record.ID == "" {
		return TOTPRecord{}, nil, ErrSecurityStateUnavailable
	}

	seed, err := s.seeds.Open(scope.AccountID, record.Ciphertext)
	if err != nil || len(seed) != 20 {
		return TOTPRecord{}, nil, ErrSecurityStateUnavailable
	}

	return record, seed, nil
}

func (s *MFAService) ConfirmTOTP(ctx context.Context, principal Principal, code string) error {
	scope, _, err := s.recentScope(ctx, principal)
	if err != nil {
		return err
	}

	return s.confirmTOTP(ctx, scope, code)
}

func (s *MFAService) confirmTOTP(ctx context.Context, scope AccountScope, code string) error {
	record, seed, err := s.readTOTP(ctx, scope)
	if err != nil {
		return err
	}
	defer clear(seed)

	now := s.now().UTC()
	if record.ConfirmedAt != nil || record.EnrollmentVersion != scope.AuthVersion ||
		now.Before(record.CreatedAt) ||
		!now.Before(record.ExpiresAt) {
		return ErrInvalidCredential
	}

	step, ok := matchingTOTPStep(seed, code, now, record.LastStep)
	if !ok {
		return ErrInvalidCredential
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return mfaStoreError(s.store.ConfirmTOTP(operation, scope, record.ID, step, now))
}

func (s *MFAService) VerifySecondFactor(
	ctx context.Context,
	factor FactorContext,
	proof SecondFactorProof,
) (string, error) {
	scope := factor.AccountScope
	if factor.Binding == ([32]byte{}) {
		return "", ErrInvalidCredential
	}

	account, err := readAccount(ctx, s.store, scope.AccountID)
	if err != nil {
		return "", err
	}
	if scope.Purpose != SessionAdmin || !scope.Allows(account) {
		return "", ErrInvalidCredential
	}

	switch proof.Method {
	case "passkey":
		if err := s.passkeys.finishPersonalLogin(
			ctx,
			factor,
			proof.CeremonyID,
			proof.Response,
		); err != nil {
			return "", err
		}

		return "passkey", nil
	case "recovery":
		if err := s.recovery.ConsumeRecoveryCode(ctx, scope, proof.Code); err != nil {
			return "", err
		}

		return "recovery", nil
	case "totp":
		record, seed, err := s.readTOTP(ctx, scope)
		if err != nil {
			return "", err
		}
		defer clear(seed)

		if record.ConfirmedAt == nil {
			return "", ErrInvalidCredential
		}

		now := s.now().UTC()
		step, ok := matchingTOTPStep(seed, proof.Code, now, record.LastStep)
		if !ok {
			return "", ErrInvalidCredential
		}

		operation, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if err := s.store.ConsumeTOTP(operation, scope, record.ID, step, now); err != nil {
			return "", mfaStoreError(err)
		}

		return "totp", nil
	default:
		return "", ErrInvalidCredential
	}
}

func (s *MFAService) RemoveTOTP(ctx context.Context, principal Principal) error {
	scope, _, err := s.recentScope(ctx, principal)
	if err != nil {
		return err
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return mfaStoreError(s.store.RemoveTOTP(operation, scope))
}

func mfaStoreError(err error) error {
	if err == nil || errors.Is(err, ErrInvalidCredential) || errors.Is(err, ErrLastMFA) ||
		errors.Is(err, ErrFactorExists) || errors.Is(err, ErrFactorLimit) {
		return err
	}

	return ErrSecurityStateUnavailable
}
