package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const MaxPasskeys = 12

var ErrFactorLimit = errors.New("passkey limit reached")

type (
	NamedCredential struct {
		Name       string
		Credential webauthn.Credential `json:"-"`
		CreatedAt  time.Time
	}
	PasskeyInfo struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		CreatedAt  time.Time  `json:"created_at"`
		LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	}
)

type FactorState struct {
	Passkeys               []PasskeyInfo `json:"passkeys"`
	TOTP                   bool          `json:"totp_enabled"`
	RecoveryCodesRemaining int           `json:"recovery_codes_remaining"`
}

// SignInMethods exposes availability only after a current password proof.
// Credential names and identifiers are reserved for authenticated settings.
type SignInMethods struct {
	Passkey  bool `json:"passkey"`
	TOTP     bool `json:"totp"`
	Recovery bool `json:"recovery"`
}

func (s *MFAService) SignInMethods(
	ctx context.Context,
	factor FactorContext,
) (SignInMethods, error) {
	if factor.Binding == ([32]byte{}) {
		return SignInMethods{}, ErrInvalidCredential
	}

	account, err := readAccount(ctx, s.store, factor.AccountID)
	if err != nil {
		return SignInMethods{}, err
	}
	if factor.Purpose != SessionAdmin || !factor.Allows(account) {
		return SignInMethods{}, ErrInvalidCredential
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	state, err := s.store.FactorState(operation, factor.AccountScope)
	if err != nil {
		return SignInMethods{}, mfaStoreError(err)
	}

	return SignInMethods{
		Passkey:  len(state.Passkeys) > 0,
		TOTP:     state.TOTP,
		Recovery: state.RecoveryCodesRemaining > 0,
	}, nil
}

func (s *MFAService) RegenerateRecoveryCodes(
	ctx context.Context,
	principal Principal,
) ([]string, error) {
	scope, _, err := s.recentScope(ctx, principal)
	if err != nil {
		return nil, err
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	state, err := s.store.FactorState(operation, scope)
	if err != nil {
		return nil, mfaStoreError(err)
	}
	if len(state.Passkeys) == 0 && !state.TOTP {
		return nil, ErrLastMFA
	}

	return s.recovery.GenerateRecoveryCodes(operation, scope, 10)
}

type personalCeremony struct {
	Scope   AccountScope
	Binding [32]byte
	Name    string
	Session webauthn.SessionData
}

func (s *MFAService) BeginPasskeyEnrollment(
	ctx context.Context,
	principal Principal,
	name string,
) (BeginCeremony, error) {
	scope, _, err := s.recentScope(ctx, principal)
	if err != nil {
		return BeginCeremony{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 80 {
		return BeginCeremony{}, ErrInvalidCredential
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return BeginCeremony{}, ErrInvalidCredential
		}
	}
	return s.passkeys.beginPersonalEnrollment(ctx, scope, name)
}

func (s *MFAService) FinishPasskeyEnrollment(
	ctx context.Context,
	principal Principal,
	id string,
	response []byte,
) error {
	scope, _, err := s.recentScope(ctx, principal)
	if err != nil {
		return err
	}
	return s.passkeys.finishPersonalEnrollment(ctx, scope, id, response)
}

func (s *MFAService) BeginPasskeyLogin(
	ctx context.Context,
	factor FactorContext,
) (BeginCeremony, error) {
	if factor.Binding == ([32]byte{}) {
		return BeginCeremony{}, ErrInvalidCredential
	}

	return s.passkeys.beginPersonalLogin(ctx, factor)
}

func (s *MFAService) Factors(ctx context.Context, principal Principal) (FactorState, error) {
	scope, _, err := s.currentScope(ctx, principal)
	if err != nil {
		return FactorState{}, err
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	state, err := s.store.FactorState(operation, scope)
	if err != nil {
		return FactorState{}, mfaStoreError(err)
	}

	return state, nil
}

func (s *MFAService) RemovePasskey(ctx context.Context, principal Principal, id string) error {
	scope, _, err := s.recentScope(ctx, principal)
	if err != nil {
		return err
	}

	raw, err := base64.RawURLEncoding.Strict().DecodeString(id)
	if err != nil || len(raw) < 1 || len(raw) > 1024 {
		return ErrInvalidCredential
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return mfaStoreError(s.store.RemovePasskey(operation, scope, raw))
}

func (s *PasskeyService) personalUser(
	ctx context.Context,
	scope AccountScope,
) (passkeyUser, error) {
	account, err := readAccount(ctx, s.store, scope.AccountID)
	if err != nil {
		return passkeyUser{}, err
	}
	if scope.Purpose != SessionAdmin || !scope.Allows(account) {
		return passkeyUser{}, ErrInvalidCredential
	}
	if len(account.UserHandle) < 1 || len(account.UserHandle) > 64 {
		return passkeyUser{}, ErrSecurityStateUnavailable
	}
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	credentials, err := s.store.Credentials(operation, account.UserHandle)
	if err != nil {
		return passkeyUser{}, ErrSecurityStateUnavailable
	}
	return passkeyUser{
		handle:      account.UserHandle,
		name:        account.Email,
		credentials: credentials,
	}, nil
}

func (s *PasskeyService) beginPersonalEnrollment(
	ctx context.Context,
	scope AccountScope,
	name string,
) (BeginCeremony, error) {
	user, err := s.personalUser(ctx, scope)
	if err != nil {
		return BeginCeremony{}, err
	}
	if len(user.credentials) >= MaxPasskeys {
		return BeginCeremony{}, ErrFactorLimit
	}
	options, session, err := s.webAuthn.BeginRegistration(
		user,
		webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()),
	)
	if err != nil {
		return BeginCeremony{}, ErrInvalidCredential
	}
	payload, err := json.Marshal(personalCeremony{Scope: scope, Name: name, Session: *session})
	if err != nil {
		return BeginCeremony{}, ErrSecurityStateUnavailable
	}
	return s.saveCeremonyPayload(ctx, "account.register", options, payload)
}

func (s *PasskeyService) finishPersonalEnrollment(
	ctx context.Context,
	scope AccountScope,
	id string,
	response []byte,
) error {
	envelope, err := s.personalCeremony(ctx, id, "account.register")
	if err != nil {
		return err
	}
	if envelope.Scope != scope || envelope.Binding != ([32]byte{}) {
		return ErrInvalidCredential
	}
	user, err := s.personalUser(ctx, scope)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return ErrInvalidCredential
	}
	credential, err := s.webAuthn.CreateCredential(user, envelope.Session, parsed)
	if err != nil {
		return ErrInvalidCredential
	}
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return mfaStoreError(
		s.store.SavePersonalCredential(
			operation,
			scope,
			NamedCredential{Name: envelope.Name, Credential: *credential, CreatedAt: s.now().UTC()},
		),
	)
}

func (s *PasskeyService) beginPersonalLogin(
	ctx context.Context,
	factor FactorContext,
) (BeginCeremony, error) {
	user, err := s.personalUser(ctx, factor.AccountScope)
	if err != nil {
		return BeginCeremony{}, err
	}
	options, session, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		return BeginCeremony{}, ErrInvalidCredential
	}
	payload, err := json.Marshal(
		personalCeremony{Scope: factor.AccountScope, Binding: factor.Binding, Session: *session},
	)
	if err != nil {
		return BeginCeremony{}, ErrSecurityStateUnavailable
	}
	return s.saveCeremonyPayload(ctx, "account.login", options, payload)
}

func (s *PasskeyService) finishPersonalLogin(
	ctx context.Context,
	factor FactorContext,
	id string,
	response []byte,
) error {
	envelope, err := s.personalCeremony(ctx, id, "account.login")
	if err != nil {
		return err
	}
	if envelope.Scope != factor.AccountScope || envelope.Binding != factor.Binding {
		return ErrInvalidCredential
	}
	user, err := s.personalUser(ctx, factor.AccountScope)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return ErrInvalidCredential
	}
	credential, err := s.webAuthn.ValidateLogin(user, envelope.Session, parsed)
	if err != nil {
		return ErrInvalidCredential
	}
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return mfaStoreError(
		s.store.UpdatePersonalCredential(
			operation,
			factor.AccountScope,
			*credential,
			s.now().UTC(),
		),
	)
}

func (s *PasskeyService) personalCeremony(
	ctx context.Context,
	id, kind string,
) (personalCeremony, error) {
	_, payload, err := s.consumeCeremonyPayload(ctx, id, kind)
	if err != nil {
		if errors.Is(err, ErrSecurityStateUnavailable) {
			return personalCeremony{}, err
		}

		return personalCeremony{}, ErrInvalidCredential
	}

	var value personalCeremony
	if json.Unmarshal(payload, &value) != nil {
		return personalCeremony{}, ErrInvalidCredential
	}

	return value, nil
}
