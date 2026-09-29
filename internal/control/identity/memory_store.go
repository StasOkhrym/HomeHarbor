package identity

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type MemoryStore struct {
	mu            sync.Mutex
	recoveryCodes map[[32]byte]RecoveryCode
	sessions      map[[32]byte]Session
	ceremonies    map[[32]byte]Ceremony
	credentials   map[string][]webauthn.Credential
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{recoveryCodes: make(map[[32]byte]RecoveryCode), sessions: make(map[[32]byte]Session), ceremonies: make(map[[32]byte]Ceremony), credentials: make(map[string][]webauthn.Credential)}
}

func (s *MemoryStore) SaveRecoveryCodes(_ context.Context, codes []RecoveryCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Generating a replacement set invalidates every older unused code. Keeping
	// both sets would make a supposedly rotated emergency credential valid.
	s.recoveryCodes = make(map[[32]byte]RecoveryCode, len(codes))
	for _, code := range codes {
		s.recoveryCodes[code.Hash] = code
	}
	return nil
}

func (s *MemoryStore) ConsumeRecoveryCode(_ context.Context, hash [32]byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.recoveryCodes[hash]
	if !ok || code.UsedAt != nil {
		return ErrInvalidCredential
	}
	code.UsedAt = &now
	s.recoveryCodes[hash] = code
	return nil
}

func (s *MemoryStore) SaveSession(_ context.Context, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.Hash] = session
	return nil
}

func (s *MemoryStore) Session(_ context.Context, hash [32]byte) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[hash]
	if !ok {
		return Session{}, ErrInvalidCredential
	}
	return session, nil
}

func (s *MemoryStore) RevokeSession(_ context.Context, hash [32]byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[hash]
	if !ok {
		return ErrInvalidCredential
	}
	if session.RevokedAt == nil {
		session.RevokedAt = &now
		s.sessions[hash] = session
	}
	return nil
}

func (s *MemoryStore) ContainsPlaintext(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash := range s.recoveryCodes {
		if bytes.Contains(hash[:], []byte(value)) {
			return true
		}
	}
	return false
}

func (s *MemoryStore) HasCredentials(_ context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, credentials := range s.credentials {
		if len(credentials) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (s *MemoryStore) Credentials(_ context.Context, userHandle []byte) ([]webauthn.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credentials := s.credentials[string(userHandle)]
	return append([]webauthn.Credential(nil), credentials...), nil
}

func (s *MemoryStore) Credential(_ context.Context, userHandle, credentialID []byte) (webauthn.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, credential := range s.credentials[string(userHandle)] {
		if bytes.Equal(credential.ID, credentialID) {
			return credential, nil
		}
	}
	return webauthn.Credential{}, ErrInvalidCredential
}

func (s *MemoryStore) SaveCredential(_ context.Context, userHandle []byte, credential webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(userHandle)
	// The first credential closes bootstrap under the same lock that performs
	// the insert; two valid, concurrently finished ceremonies cannot both win.
	if len(s.credentials[key]) != 0 {
		return ErrBootstrapClosed
	}
	s.credentials[key] = append(s.credentials[key], credential)
	return nil
}

func (s *MemoryStore) UpdateCredential(_ context.Context, userHandle []byte, credential webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(userHandle)
	for index, stored := range s.credentials[key] {
		if bytes.Equal(stored.ID, credential.ID) {
			if stored.Authenticator.SignCount > 0 && credential.Authenticator.SignCount <= stored.Authenticator.SignCount {
				return ErrInvalidCredential
			}
			s.credentials[key][index] = credential
			return nil
		}
	}
	return ErrInvalidCredential
}

func (s *MemoryStore) SaveCeremony(_ context.Context, ceremony Ceremony) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ceremonies[ceremony.IDHash] = ceremony
	return nil
}

func (s *MemoryStore) ConsumeCeremony(_ context.Context, hash [32]byte, now time.Time) (Ceremony, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ceremony, ok := s.ceremonies[hash]
	if !ok || ceremony.ConsumedAt != nil || !now.Before(ceremony.ExpiresAt) {
		return Ceremony{}, ErrInvalidCeremony
	}
	ceremony.ConsumedAt = &now
	s.ceremonies[hash] = ceremony
	return ceremony, nil
}
