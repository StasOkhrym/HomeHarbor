package devices

import (
	"context"
	"sync"
	"time"
)

type MemoryStore struct {
	mu      sync.Mutex
	tokens  map[[32]byte]EnrollmentToken
	devices map[string]Device
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{tokens: make(map[[32]byte]EnrollmentToken), devices: make(map[string]Device)}
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
	return nil
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
func (s *MemoryStore) AuthenticateCredential(_ context.Context, hash [32]byte, _ time.Time) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, device := range s.devices {
		if device.CredentialHash == hash && device.Status == StatusActive {
			return device, nil
		}
	}
	return Device{}, ErrDeviceNotFound
}
