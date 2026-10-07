package devices

import (
	"context"
	"slices"
	"sync"
	"time"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/devices"
)

type Repository struct {
	mu                sync.Mutex
	tokens            map[[32]byte]domainpkg.EnrollmentToken
	devices           map[string]domainpkg.Device
	credentialExpires map[string]time.Time
}

func NewRepository() *Repository {
	return &Repository{
		tokens:            make(map[[32]byte]domainpkg.EnrollmentToken),
		devices:           make(map[string]domainpkg.Device),
		credentialExpires: make(map[string]time.Time),
	}
}

func (s *Repository) SaveEnrollmentToken(
	ctx context.Context,
	token domainpkg.EnrollmentToken,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Hash] = cloneToken(token)
	return nil
}

// SeedDevice sets up a device fixture without consuming an enrollment token.
func (s *Repository) SeedDevice(ctx context.Context, device domainpkg.Device) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkUnique(device); err != nil {
		return err
	}
	device.Credential = ""
	s.devices[device.ID] = cloneDevice(device)
	s.credentialExpires[device.ID] = device.CredentialExpiration()
	return nil
}

func (s *Repository) Enroll(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
	device domainpkg.Device,
) (domainpkg.Role, error) {
	if err := ctx.Err(); err != nil {
		var zero domainpkg.Role
		return zero, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokens[hash]
	if !ok || token.UsedAt != nil || !now.Before(token.ExpiresAt) {
		return "", domainpkg.ErrInvalidEnrollmentToken
	}
	if err := s.checkUnique(device); err != nil {
		return "", err
	}
	token.UsedAt = &now
	s.tokens[hash] = token
	device.Role = token.Role
	device.Credential = ""
	s.devices[device.ID] = cloneDevice(device)
	s.credentialExpires[device.ID] = device.CredentialExpiration()
	return token.Role, nil
}

// checkUnique is called with mu held, before consuming a one-time token.
func (s *Repository) checkUnique(device domainpkg.Device) error {
	for _, current := range s.devices {
		if current.ID == device.ID || current.IdentityPublicKey == device.IdentityPublicKey ||
			current.WireGuardPublicKey == device.WireGuardPublicKey {
			return domainpkg.ErrDeviceConflict
		}
	}
	return nil
}

func (s *Repository) Device(ctx context.Context, id string) (domainpkg.Device, error) {
	if err := ctx.Err(); err != nil {
		var zero domainpkg.Device
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.devices[id]
	if !ok {
		return domainpkg.Device{}, domainpkg.ErrDeviceNotFound
	}

	return cloneDevice(d), nil
}

func (s *Repository) ListDevices(ctx context.Context) ([]domainpkg.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]domainpkg.Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, cloneDevice(d))
	}

	slices.SortFunc(out, func(a, b domainpkg.Device) int {
		if n := a.CreatedAt.Compare(b.CreatedAt); n != 0 {
			return n
		}

		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}

		return 0
	})
	return out, nil
}

func (s *Repository) RevokeDevice(ctx context.Context, id string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.devices[id]
	if !ok {
		return domainpkg.ErrDeviceNotFound
	}
	if d.Status == domainpkg.StatusRevoked {
		return nil
	}

	d.Status = domainpkg.StatusRevoked
	d.RevokedAt = &at
	s.devices[id] = d

	return nil
}

func (s *Repository) AuthenticateCredential(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (domainpkg.Device, error) {
	if err := ctx.Err(); err != nil {
		var zero domainpkg.Device
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, device := range s.devices {
		if device.CredentialHash == hash && device.Status == domainpkg.StatusActive &&
			now.Before(s.credentialExpires[device.ID]) {
			device.CredentialExpiresAt = s.credentialExpires[device.ID]
			return cloneDevice(device), nil
		}
	}

	return domainpkg.Device{}, domainpkg.ErrDeviceNotFound
}

func cloneDevice(device domainpkg.Device) domainpkg.Device {
	if device.RevokedAt != nil {
		at := *device.RevokedAt
		device.RevokedAt = &at
	}

	return device
}

func cloneToken(token domainpkg.EnrollmentToken) domainpkg.EnrollmentToken {
	if token.UsedAt != nil {
		at := *token.UsedAt
		token.UsedAt = &at
	}

	return token
}

var _ domainpkg.Repository = (*Repository)(nil)

func (s *Repository) RotateCredential(
	ctx context.Context,
	id string,
	oldHash, newHash [32]byte,
	now, expiresAt time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[id]
	if !ok || device.Status != domainpkg.StatusActive || device.CredentialHash != oldHash ||
		!now.Before(s.credentialExpires[id]) {
		return domainpkg.ErrDeviceNotFound
	}
	device.CredentialHash = newHash
	s.devices[id] = device
	s.credentialExpires[id] = expiresAt
	return nil
}
