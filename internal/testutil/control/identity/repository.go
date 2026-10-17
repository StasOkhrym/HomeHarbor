package identity

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/identity"
)

type Repository struct {
	passkeyInfo   map[string]domainpkg.PasskeyInfo
	totp          map[string]domainpkg.TOTPRecord
	preauth       map[[32]byte]domainpkg.Preauth
	mu            sync.Mutex
	recoveryCodes map[string]map[[32]byte]domainpkg.RecoveryCode
	accounts      map[string]domainpkg.Account
	sessions      map[[32]byte]domainpkg.Session
	ceremonies    map[[32]byte]domainpkg.Ceremony
	credentials   map[string][]webauthn.Credential
}

func NewRepository() *Repository {
	return &Repository{
		recoveryCodes: make(map[string]map[[32]byte]domainpkg.RecoveryCode),
		accounts: map[string]domainpkg.Account{
			domainpkg.OwnerAccountID: {
				ID:          domainpkg.OwnerAccountID,
				Role:        domainpkg.RoleOwner,
				Status:      domainpkg.AccountSetup,
				AuthVersion: 1,
				UserHandle:  []byte("homeharbor-admin-v1"),
			},
		},
		sessions:    make(map[[32]byte]domainpkg.Session),
		ceremonies:  make(map[[32]byte]domainpkg.Ceremony),
		credentials: make(map[string][]webauthn.Credential),
	}
}

// StoredCeremony returns a copy for at-rest encryption assertions in tests.
func (s *Repository) StoredCeremony(hash [32]byte) (domainpkg.Ceremony, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.ceremonies[hash]

	return cloneCeremony(value), ok
}

func (s *Repository) CeremonyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.ceremonies)
}

func (s *Repository) SaveRecoveryCodes(
	ctx context.Context,
	scope domainpkg.AccountScope,
	codes []domainpkg.RecoveryCode,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !scope.Allows(s.accounts[scope.AccountID]) {
		return domainpkg.ErrInvalidCredential
	}
	// Generating a replacement set invalidates every older unused code. Keeping
	// both sets would make a supposedly rotated emergency credential valid.
	s.recoveryCodes[scope.AccountID] = make(map[[32]byte]domainpkg.RecoveryCode, len(codes))
	for _, code := range codes {
		s.recoveryCodes[scope.AccountID][code.Hash] = cloneRecoveryCode(code)
	}
	return nil
}

func (s *Repository) ConsumeRecoveryCode(ctx context.Context, use domainpkg.RecoveryUse) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scope := use.Scope
	hash := use.Hash
	now := use.UsedAt
	s.mu.Lock()
	defer s.mu.Unlock()
	if !scope.Allows(s.accounts[scope.AccountID]) {
		return domainpkg.ErrInvalidCredential
	}
	code, ok := s.recoveryCodes[scope.AccountID][hash]
	if !ok || code.UsedAt != nil {
		return domainpkg.ErrInvalidCredential
	}
	code.UsedAt = &now
	s.recoveryCodes[scope.AccountID][hash] = code
	return nil
}

func (s *Repository) SaveSession(ctx context.Context, session domainpkg.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.Hash] = cloneSession(session)

	return nil
}

func (s *Repository) Session(ctx context.Context, hash [32]byte) (domainpkg.Session, error) {
	if err := ctx.Err(); err != nil {
		var zero domainpkg.Session
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[hash]
	if !ok {
		return domainpkg.Session{}, domainpkg.ErrInvalidCredential
	}

	return cloneSession(session), nil
}

func (s *Repository) RevokeSession(ctx context.Context, hash [32]byte, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[hash]
	if !ok {
		return domainpkg.ErrInvalidCredential
	}

	if session.RevokedAt == nil {
		session.RevokedAt = &now
		s.sessions[hash] = session
	}

	return nil
}

func (s *Repository) ContainsPlaintext(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, codes := range s.recoveryCodes {
		for hash := range codes {
			if bytes.Contains(hash[:], []byte(value)) {
				return true
			}
		}
	}

	return false
}

func (s *Repository) HasCredentials(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		var zero bool
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, credentials := range s.credentials {
		if len(credentials) > 0 {
			return true, nil
		}
	}

	return false, nil
}

func (s *Repository) Credentials(
	ctx context.Context,
	userHandle []byte,
) ([]webauthn.Credential, error) {
	if err := ctx.Err(); err != nil {
		var zero []webauthn.Credential
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	credentials := s.credentials[string(userHandle)]
	out := make([]webauthn.Credential, len(credentials))
	for index, credential := range credentials {
		out[index] = cloneCredential(credential)
	}

	return out, nil
}

func (s *Repository) Credential(
	ctx context.Context,
	userHandle, credentialID []byte,
) (webauthn.Credential, error) {
	if err := ctx.Err(); err != nil {
		var zero webauthn.Credential
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, credential := range s.credentials[string(userHandle)] {
		if bytes.Equal(credential.ID, credentialID) {
			return cloneCredential(credential), nil
		}
	}

	return webauthn.Credential{}, domainpkg.ErrInvalidCredential
}

func (s *Repository) SaveBootstrapCredential(
	ctx context.Context,
	userHandle []byte,
	credential webauthn.Credential,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	owner, ok := s.accounts[domainpkg.OwnerAccountID]
	if !ok || owner.Status != domainpkg.AccountSetup || !bytes.Equal(owner.UserHandle, userHandle) {
		return domainpkg.ErrBootstrapClosed
	}
	// The first credential closes bootstrap under the same lock that performs
	// the insert; two valid, concurrently finished ceremonies cannot both win.
	if len(s.credentials[string(userHandle)]) != 0 {
		return domainpkg.ErrBootstrapClosed
	}

	s.credentials[string(userHandle)] = append(
		s.credentials[string(userHandle)],
		cloneCredential(credential),
	)

	return nil
}

func (s *Repository) UpdateCredential(
	ctx context.Context,
	userHandle []byte,
	credential webauthn.Credential,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for index, stored := range s.credentials[string(userHandle)] {
		if bytes.Equal(stored.ID, credential.ID) {
			if stored.Authenticator.SignCount > 0 &&
				credential.Authenticator.SignCount <= stored.Authenticator.SignCount {
				return domainpkg.ErrInvalidCredential
			}

			s.credentials[string(userHandle)][index] = cloneCredential(credential)

			return nil
		}
	}

	return domainpkg.ErrInvalidCredential
}

func (s *Repository) SaveCeremony(ctx context.Context, ceremony domainpkg.Ceremony) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ceremonies[ceremony.IDHash] = cloneCeremony(ceremony)

	return nil
}

func (s *Repository) ConsumeCeremony(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (domainpkg.Ceremony, error) {
	if err := ctx.Err(); err != nil {
		var zero domainpkg.Ceremony
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ceremony, ok := s.ceremonies[hash]
	if !ok || ceremony.ConsumedAt != nil || !now.Before(ceremony.ExpiresAt) {
		return domainpkg.Ceremony{}, domainpkg.ErrInvalidCeremony
	}

	ceremony.ConsumedAt = &now
	s.ceremonies[hash] = ceremony

	return cloneCeremony(ceremony), nil
}

func cloneRecoveryCode(value domainpkg.RecoveryCode) domainpkg.RecoveryCode {
	if value.UsedAt != nil {
		at := *value.UsedAt
		value.UsedAt = &at
	}

	return value
}

func cloneSession(value domainpkg.Session) domainpkg.Session {
	if value.RevokedAt != nil {
		at := *value.RevokedAt
		value.RevokedAt = &at
	}

	return value
}

func cloneCeremony(value domainpkg.Ceremony) domainpkg.Ceremony {
	value.PayloadCiphertext = bytes.Clone(value.PayloadCiphertext)
	if value.ConsumedAt != nil {
		at := *value.ConsumedAt
		value.ConsumedAt = &at
	}

	return value
}

func cloneCredential(value webauthn.Credential) webauthn.Credential {
	value.ID = bytes.Clone(value.ID)
	value.PublicKey = bytes.Clone(value.PublicKey)
	value.Transport = slices.Clone(value.Transport)
	value.Authenticator.AAGUID = bytes.Clone(value.Authenticator.AAGUID)
	value.Attestation.ClientDataJSON = bytes.Clone(value.Attestation.ClientDataJSON)
	value.Attestation.ClientDataHash = bytes.Clone(value.Attestation.ClientDataHash)
	value.Attestation.AuthenticatorData = bytes.Clone(value.Attestation.AuthenticatorData)
	value.Attestation.Object = bytes.Clone(value.Attestation.Object)

	return value
}

var (
	_ domainpkg.Repository         = (*Repository)(nil)
	_ domainpkg.SessionRepository  = (*Repository)(nil)
	_ domainpkg.PasskeyRepository  = (*Repository)(nil)
	_ domainpkg.CeremonyRepository = (*Repository)(nil)
)

// SetAccountForTest represents a committed SQL account change for domain tests.
func (s *Repository) SetAccountForTest(account domainpkg.Account) {
	s.mu.Lock()
	defer s.mu.Unlock()

	account = cloneAccount(account)
	s.accounts[account.ID] = account
}

func (s *Repository) Account(ctx context.Context, id string) (domainpkg.Account, error) {
	if err := ctx.Err(); err != nil {
		return domainpkg.Account{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	account, ok := s.accounts[id]
	if !ok {
		return domainpkg.Account{}, domainpkg.ErrInvalidCredential
	}

	return cloneAccount(account), nil
}

func cloneAccount(account domainpkg.Account) domainpkg.Account {
	account.UserHandle = bytes.Clone(account.UserHandle)
	if account.EmailVerifiedAt != nil {
		value := *account.EmailVerifiedAt
		account.EmailVerifiedAt = &value
	}

	return account
}
