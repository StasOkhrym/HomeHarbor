package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"strings"
	"time"
)

// Preauth records password proof, not administrative authority. It is admitted
// for at most five factor attempts, then atomically consumed before any session.
type Preauth struct {
	Hash        [32]byte
	AccountID   string
	AuthVersion uint64
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Attempts    int
}
type (
	IssuedPreauth struct {
		Token     string
		ExpiresAt time.Time
	}
	SecondFactorProof struct {
		Method     string          `json:"method"`
		Code       string          `json:"code,omitempty"`
		CeremonyID string          `json:"ceremony_id,omitempty"`
		Response   json.RawMessage `json:"response,omitempty"`
	}
)

type (
	SecondFactorVerifier interface {
		VerifySecondFactor(context.Context, AccountScope, SecondFactorProof) (string, error)
	}
	PreauthRepository interface {
		SavePreauth(context.Context, Preauth) error
		AttemptPreauth(context.Context, [32]byte, time.Time) (Preauth, error)
		ConsumePreauth(context.Context, [32]byte, time.Time) (Preauth, error)
	}
)

type PasswordAccounts interface {
	AccountReader
	AccountByEmail(context.Context, string) (Account, error)
	ConfigureOwner(context.Context, AccountScope, string, string) error
}
type (
	SessionIssuer interface {
		CreateSession(context.Context, SessionRequest) (IssuedSession, error)
	}
	LoginConfig  struct{ SessionTTL time.Duration }
	LoginService struct {
		accounts   PasswordAccounts
		preauth    PreauthRepository
		sessions   SessionIssuer
		passwords  *PasswordHasher
		now        func() time.Time
		random     io.Reader
		sessionTTL time.Duration
	}
)

func NewLoginService(
	config LoginConfig,
	accounts PasswordAccounts,
	preauth PreauthRepository,
	sessions SessionIssuer,
	passwords *PasswordHasher,
	now func() time.Time,
	random io.Reader,
) (*LoginService, error) {
	if accounts == nil || preauth == nil || sessions == nil || passwords == nil ||
		config.SessionTTL <= 0 {
		return nil, errors.New(
			"account, preauth, session and password authorities with positive session TTL are required",
		)
	}

	if now == nil {
		now = time.Now
	}

	if random == nil {
		random = rand.Reader
	}

	return &LoginService{
		accounts:   accounts,
		preauth:    preauth,
		sessions:   sessions,
		passwords:  passwords,
		now:        now,
		random:     random,
		sessionTTL: config.SessionTTL,
	}, nil
}

func CanonicalEmail(input string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(input))
	if len(email) < 3 || len(email) > 254 {
		return "", ErrInvalidCredential
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || parsed.Name != "" {
		return "", ErrInvalidCredential
	}
	return email, nil
}

func (s *LoginService) Password(
	ctx context.Context,
	input, password string,
) (IssuedPreauth, error) {
	email, emailErr := CanonicalEmail(input)
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var account Account

	err := ErrInvalidCredential
	if emailErr == nil {
		account, err = s.accounts.AccountByEmail(operation, email)
	}

	if err != nil && !errors.Is(err, ErrInvalidCredential) {
		return IssuedPreauth{}, ErrSecurityStateUnavailable
	}

	// Missing/revoked/invited accounts still take the same bounded password path.
	verifyErr := s.passwords.Verify(ctx, account.PasswordHash, password)
	if verifyErr != nil && !errors.Is(verifyErr, ErrInvalidCredential) {
		return IssuedPreauth{}, securityStoreError(verifyErr)
	}

	now := s.now().UTC()
	if err != nil || verifyErr != nil || account.Email != email {
		return IssuedPreauth{}, ErrInvalidCredential
	}

	if _, err := account.Principal(
		Session{
			AccountID:   account.ID,
			AuthVersion: account.AuthVersion,
			Purpose:     SessionAdmin,
			Method:      "totp",
			CreatedAt:   now,
			ExpiresAt:   now.Add(time.Minute),
		},
	); err != nil {
		return IssuedPreauth{}, ErrInvalidCredential
	}

	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(s.random, tokenBytes); err != nil {
		return IssuedPreauth{}, ErrSecurityStateUnavailable
	}

	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	record := Preauth{
		Hash:        hashToken(token),
		AccountID:   account.ID,
		AuthVersion: account.AuthVersion,
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}
	operation, cancelSave := context.WithTimeout(ctx, 5*time.Second)
	defer cancelSave()

	if err := s.preauth.SavePreauth(operation, record); err != nil {
		return IssuedPreauth{}, securityStoreError(err)
	}

	return IssuedPreauth{Token: token, ExpiresAt: record.ExpiresAt}, nil
}

func (s *LoginService) Complete(
	ctx context.Context,
	token string,
	proof SecondFactorProof,
	verifier SecondFactorVerifier,
) (IssuedSession, error) {
	if len(token) < 1 || len(token) > 128 || verifier == nil {
		return IssuedSession{}, ErrInvalidCredential
	}
	hash := hashToken(token)
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	record, err := s.preauth.AttemptPreauth(operation, hash, s.now().UTC())
	cancel()
	if err != nil {
		return IssuedSession{}, securityStoreError(err)
	}
	if err := s.validPreauth(record, hash); err != nil {
		return IssuedSession{}, err
	}
	account, err := readAccount(ctx, s.accounts, record.AccountID)
	if err != nil {
		return IssuedSession{}, err
	}
	scope := AccountScope{
		AccountID:   record.AccountID,
		AuthVersion: record.AuthVersion,
		Purpose:     SessionAdmin,
	}
	if !scope.Allows(account) {
		return IssuedSession{}, ErrInvalidCredential
	}
	method, err := verifier.VerifySecondFactor(ctx, scope, proof)
	if err != nil {
		return IssuedSession{}, securityStoreError(err)
	}
	switch method {
	case "totp", "passkey", "recovery":
	default:
		return IssuedSession{}, ErrInvalidCredential
	}
	operation, cancel = context.WithTimeout(ctx, 5*time.Second)
	consumed, err := s.preauth.ConsumePreauth(operation, hash, s.now().UTC())
	cancel()
	if err != nil {
		return IssuedSession{}, securityStoreError(err)
	}
	if err := s.validPreauth(consumed, hash); err != nil {
		return IssuedSession{}, err
	}
	if consumed.AccountID != record.AccountID || consumed.AuthVersion != record.AuthVersion {
		return IssuedSession{}, ErrInvalidCredential
	}
	// A session-store outage after consumption requires a new password login;
	// retrying the old proof can never mint a second session.
	return s.sessions.CreateSession(
		ctx,
		SessionRequest{
			AccountID:   scope.AccountID,
			AuthVersion: scope.AuthVersion,
			Purpose:     SessionAdmin,
			Method:      method,
			TTL:         s.sessionTTL,
		},
	)
}

func (s *LoginService) validPreauth(record Preauth, hash [32]byte) error {
	now := s.now().UTC()
	if record.Hash != hash || record.AccountID == "" || record.AuthVersion == 0 ||
		record.CreatedAt.IsZero() ||
		now.Before(record.CreatedAt) ||
		!now.Before(record.ExpiresAt) ||
		!record.ExpiresAt.After(record.CreatedAt) ||
		record.ExpiresAt.Sub(record.CreatedAt) > 5*time.Minute ||
		record.Attempts < 1 ||
		record.Attempts > 5 {
		return ErrInvalidCredential
	}
	return nil
}
