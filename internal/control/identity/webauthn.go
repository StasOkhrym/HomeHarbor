package identity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrInvalidCeremony          = errors.New("invalid or expired ceremony")
	ErrBootstrapClosed          = errors.New("passkey bootstrap is already complete")
	ErrSecurityStateUnavailable = errors.New("security state unavailable")
)

var adminUserHandle = []byte("go-tunnels-admin-v1")

type Ceremony struct {
	IDHash            [32]byte
	Kind              string
	PayloadCiphertext []byte
	ExpiresAt         time.Time
	ConsumedAt        *time.Time
}

type PasskeyRepository interface {
	HasCredentials(context.Context) (bool, error)
	Credentials(context.Context, []byte) ([]webauthn.Credential, error)
	Credential(context.Context, []byte, []byte) (webauthn.Credential, error)
	SaveCredential(context.Context, []byte, webauthn.Credential) error
	UpdateCredential(context.Context, []byte, webauthn.Credential) error
}

// CeremonyRepository is ephemeral one-time proof state, independent of the
// durable passkey credentials and authenticator counters.
type CeremonyRepository interface {
	SaveCeremony(context.Context, Ceremony) error
	ConsumeCeremony(context.Context, [32]byte, time.Time) (Ceremony, error)
}

type PasskeyConfig struct {
	RPID          string
	RPOrigin      string
	EncryptionKey []byte
	CeremonyTTL   time.Duration
}

type BeginCeremony struct {
	CeremonyID string          `json:"ceremony_id"`
	Options    json.RawMessage `json:"options"`
}

type PasskeyService struct {
	store      PasskeyRepository
	ceremonies CeremonyRepository
	now        func() time.Time
	random     io.Reader
	webAuthn   *webauthn.WebAuthn
	aead       cipher.AEAD
	ttl        time.Duration
}

func NewPasskeyService(
	config PasskeyConfig,
	store PasskeyRepository,
	ceremonies CeremonyRepository,
	now func() time.Time,
	random io.Reader,
) (*PasskeyService, error) {
	if store == nil || ceremonies == nil {
		return nil, errors.New("passkey and ceremony repositories are required")
	}
	if len(config.EncryptionKey) != 32 {
		return nil, errors.New("WebAuthn ceremony encryption key must be 32 bytes")
	}
	if config.CeremonyTTL <= 0 {
		return nil, errors.New("WebAuthn ceremony TTL must be positive")
	}
	wa, err := webauthn.New(
		&webauthn.Config{
			RPID:          config.RPID,
			RPDisplayName: "Go Tunnels",
			RPOrigins:     []string{config.RPOrigin},
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				ResidentKey:      protocol.ResidentKeyRequirementRequired,
				UserVerification: protocol.VerificationRequired,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("configure WebAuthn: %w", err)
	}
	block, err := aes.NewCipher(config.EncryptionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	// Production omits the injectable reader. Nonces and ceremony identifiers
	// must still use cryptographic entropy; a supplied reader's errors propagate.
	if random == nil {
		random = rand.Reader
	}
	return &PasskeyService{
		store:      store,
		ceremonies: ceremonies,
		now:        now,
		random:     random,
		webAuthn:   wa,
		aead:       aead,
		ttl:        config.CeremonyTTL,
	}, nil
}

// HasCredentials reads setup state without allocating a one-time ceremony.
// A false result is informational; Begin/FinishBootstrap enforce exclusivity.
func (s *PasskeyService) HasCredentials(ctx context.Context) (bool, error) {
	return s.store.HasCredentials(ctx)
}

func (s *PasskeyService) BeginBootstrap(ctx context.Context) (BeginCeremony, error) {
	hasCredentials, err := s.store.HasCredentials(ctx)
	if err != nil {
		return BeginCeremony{}, err
	}
	if hasCredentials {
		return BeginCeremony{}, ErrBootstrapClosed
	}
	user, err := s.user(ctx)
	if err != nil {
		return BeginCeremony{}, err
	}
	creation, session, err := s.webAuthn.BeginRegistration(user)
	if err != nil {
		return BeginCeremony{}, err
	}
	return s.saveCeremony(ctx, "bootstrap", creation, session)
}

func (s *PasskeyService) FinishBootstrap(
	ctx context.Context,
	ceremonyID string,
	response []byte,
) (webauthn.Credential, error) {
	ceremony, session, err := s.consumeCeremony(ctx, ceremonyID, "bootstrap")
	_ = ceremony
	if err != nil {
		return webauthn.Credential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("parse registration response: %w", err)
	}
	user, err := s.user(ctx)
	if err != nil {
		return webauthn.Credential{}, err
	}
	credential, err := s.webAuthn.CreateCredential(user, session, parsed)
	if err != nil {
		return webauthn.Credential{}, err
	}
	if err = s.store.SaveCredential(ctx, adminUserHandle, *credential); err != nil {
		return webauthn.Credential{}, err
	}
	return *credential, nil
}

func (s *PasskeyService) BeginLogin(ctx context.Context) (BeginCeremony, error) {
	assertion, session, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		return BeginCeremony{}, err
	}
	return s.saveCeremony(ctx, "login", assertion, session)
}

func (s *PasskeyService) FinishLogin(
	ctx context.Context,
	ceremonyID string,
	response []byte,
) (webauthn.Credential, error) {
	_, session, err := s.consumeCeremony(ctx, ceremonyID, "login")
	if err != nil {
		return webauthn.Credential{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("parse login response: %w", err)
	}
	_, credential, err := s.webAuthn.ValidatePasskeyLogin(
		func(rawID, userHandle []byte) (webauthn.User, error) {
			if string(userHandle) != string(adminUserHandle) {
				return nil, ErrInvalidCredential
			}
			stored, lookupErr := s.store.Credential(ctx, userHandle, rawID)
			if lookupErr != nil {
				return nil, ErrInvalidCredential
			}
			return adminUser{handle: userHandle, credentials: []webauthn.Credential{stored}}, nil
		},
		session,
		parsed,
	)
	if err != nil {
		return webauthn.Credential{}, err
	}
	// The library returns the incremented sign counter. The store performs a
	// compare-and-update so cloned authenticators cannot race a stale counter in.
	if err = s.store.UpdateCredential(ctx, adminUserHandle, *credential); err != nil {
		return webauthn.Credential{}, err
	}
	return *credential, nil
}

func (s *PasskeyService) saveCeremony(
	ctx context.Context,
	kind string,
	options any,
	session *webauthn.SessionData,
) (BeginCeremony, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return BeginCeremony{}, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = io.ReadFull(s.random, nonce); err != nil {
		return BeginCeremony{}, err
	}
	// The challenge is required to validate the finish response. AES-GCM keeps
	// it confidential at rest and authenticates kind as associated data.
	ciphertext := s.aead.Seal(nonce, nonce, payload, []byte(kind))
	id, err := randomTokenFrom(s.random, 32)
	if err != nil {
		return BeginCeremony{}, err
	}
	ceremony := Ceremony{
		IDHash:            hashToken(id),
		Kind:              kind,
		PayloadCiphertext: ciphertext,
		ExpiresAt:         s.now().UTC().Add(s.ttl),
	}
	if err = s.ceremonies.SaveCeremony(ctx, ceremony); err != nil {
		return BeginCeremony{}, err
	}
	encodedOptions, err := json.Marshal(options)
	if err != nil {
		return BeginCeremony{}, err
	}
	return BeginCeremony{CeremonyID: id, Options: encodedOptions}, nil
}

func (s *PasskeyService) consumeCeremony(
	ctx context.Context,
	id, expectedKind string,
) (Ceremony, webauthn.SessionData, error) {
	ceremony, err := s.ceremonies.ConsumeCeremony(ctx, hashToken(id), s.now().UTC())
	if errors.Is(err, ErrSecurityStateUnavailable) {
		return Ceremony{}, webauthn.SessionData{}, err
	}
	if err != nil || ceremony.Kind != expectedKind {
		return Ceremony{}, webauthn.SessionData{}, ErrInvalidCeremony
	}
	nonceSize := s.aead.NonceSize()
	if len(ceremony.PayloadCiphertext) < nonceSize {
		return Ceremony{}, webauthn.SessionData{}, ErrInvalidCeremony
	}
	nonce, ciphertext := ceremony.PayloadCiphertext[:nonceSize], ceremony.PayloadCiphertext[nonceSize:]
	payload, err := s.aead.Open(nil, nonce, ciphertext, []byte(ceremony.Kind))
	if err != nil {
		return Ceremony{}, webauthn.SessionData{}, ErrInvalidCeremony
	}
	var session webauthn.SessionData
	if err = json.Unmarshal(payload, &session); err != nil {
		return Ceremony{}, webauthn.SessionData{}, ErrInvalidCeremony
	}
	return ceremony, session, nil
}

func (s *PasskeyService) user(ctx context.Context) (adminUser, error) {
	credentials, err := s.store.Credentials(ctx, adminUserHandle)
	return adminUser{handle: adminUserHandle, credentials: credentials}, err
}

type adminUser struct {
	handle      []byte
	credentials []webauthn.Credential
}

func (u adminUser) WebAuthnID() []byte                         { return u.handle }
func (u adminUser) WebAuthnName() string                       { return "admin" }
func (u adminUser) WebAuthnDisplayName() string                { return "Go Tunnels Administrator" }
func (u adminUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func randomTokenFrom(reader io.Reader, size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
