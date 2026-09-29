package devices

import (
	"context"
	"sync"
	"time"
)

type MemoryStore struct {
	mu                sync.Mutex
	tokens            map[[32]byte]EnrollmentToken
	devices           map[string]Device
	credentialExpires map[string]time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{tokens: make(map[[32]byte]EnrollmentToken), devices: make(map[string]Device), credentialExpires: make(map[string]time.Time)}
}

func (s *MemoryStore) SaveEnrollmentToken(_ context.Context, token EnrollmentToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Hash] = token
	return nil
}

func (s *MemoryStore) ConsumeEnrollmentToken(_ context.Context, hash [32]byte, now time.Time) (Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokens[hash]
	if !ok || token.UsedAt != nil || !now.Before(token.ExpiresAt) {
		return "", ErrInvalidEnrollmentToken
	}
	token.UsedAt = &now
	s.tokens[hash] = token
	return token.Role, nil
}

func (s *MemoryStore) SaveDevice(_ context.Context, device Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	device.Credential = ""
	s.devices[device.ID] = device
	s.credentialExpires[device.ID] = device.CreatedAt.Add(CredentialTTL)
	return nil
}

func (s *MemoryStore) Enroll(_ context.Context, hash [32]byte, now time.Time, device Device) (Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokens[hash]
	if !ok || token.UsedAt != nil || !now.Before(token.ExpiresAt) {
		return "", ErrInvalidEnrollmentToken
	}
	token.UsedAt = &now
	s.tokens[hash] = token
	device.Role = token.Role
	device.Credential = ""
	s.devices[device.ID] = device
	s.credentialExpires[device.ID] = device.CreatedAt.Add(CredentialTTL)
	return token.Role, nil
}

func (s *MemoryStore) Device(_ context.Context, id string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return Device{}, ErrDeviceNotFound
	}
	return d, nil
}

func (s *MemoryStore) ListDevices(_ context.Context) ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, d)
	}
	return out, nil
}

func (s *MemoryStore) RevokeDevice(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return ErrDeviceNotFound
	}
	if d.Status == StatusRevoked {
		return nil
	}
	d.Status = StatusRevoked
	d.RevokedAt = &at
	s.devices[id] = d
	return nil
}

func (s *MemoryStore) AuthenticateCredential(_ context.Context, hash [32]byte, now time.Time) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, device := range s.devices {
		if device.CredentialHash == hash && device.Status == StatusActive && now.Before(s.credentialExpires[device.ID]) {
			return device, nil
		}
	}
	return Device{}, ErrDeviceNotFound
}

func (s *MemoryStore) RotateCredential(_ context.Context, id string, oldHash, newHash [32]byte, now, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[id]
	if !ok || device.Status != StatusActive || device.CredentialHash != oldHash || !now.Before(s.credentialExpires[id]) {
		return ErrDeviceNotFound
	}
	device.CredentialHash = newHash
	s.devices[id] = device
	s.credentialExpires[id] = expiresAt
	return nil
}
