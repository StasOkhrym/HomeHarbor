package devices

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type Role string

const (
	RoleClient  Role = "client"
	RoleGateway Role = "gateway"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

var (
	ErrInvalidEnrollmentToken = errors.New("invalid or expired enrollment token")
	ErrDeviceNotFound         = errors.New("device not found")
)

type Device struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Role               Role       `json:"role"`
	Status             Status     `json:"status"`
	IdentityPublicKey  string     `json:"identity_public_key"`
	WireGuardPublicKey string     `json:"wireguard_public_key"`
	CreatedAt          time.Time  `json:"created_at"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
	// Credential is returned only by Enroll. Stores must persist CredentialHash
	// and clear this plaintext value before the device can be read again.
	Credential     string   `json:"credential,omitempty"`
	CredentialHash [32]byte `json:"-"`
}

type EnrollmentToken struct {
	Hash      [32]byte
	Role      Role
	ExpiresAt time.Time
	UsedAt    *time.Time
}

type IssuedToken struct {
	Token     string    `json:"token"`
	Role      Role      `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type EnrollRequest struct {
	Token              string `json:"token"`
	Name               string `json:"name"`
	IdentityPublicKey  string `json:"identity_public_key"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
}

type Store interface {
	SaveEnrollmentToken(context.Context, EnrollmentToken) error
	ConsumeEnrollmentToken(context.Context, [32]byte, time.Time) (Role, error)
	SaveDevice(context.Context, Device) error
	Device(context.Context, string) (Device, error)
	ListDevices(context.Context) ([]Device, error)
	RevokeDevice(context.Context, string, time.Time) error
	AuthenticateCredential(context.Context, [32]byte, time.Time) (Device, error)
}

type Service struct {
	store     Store
	now       func() time.Time
	random    io.Reader
	publisher Publisher
}

type Event struct {
	Type        string    `json:"type"`
	AggregateID string    `json:"aggregate_id"`
	OccurredAt  time.Time `json:"occurred_at"`
}
type Publisher interface {
	Publish(context.Context, Event) error
}
type Option func(*Service)

func WithPublisher(publisher Publisher) Option {
	return func(service *Service) { service.publisher = publisher }
}

func NewService(store Store, now func() time.Time, random io.Reader, options ...Option) *Service {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	service := &Service{store: store, now: now, random: random}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) IssueEnrollmentToken(ctx context.Context, role Role, ttl time.Duration) (IssuedToken, error) {
	if role != RoleClient && role != RoleGateway {
		return IssuedToken{}, fmt.Errorf("unsupported role %q", role)
	}
	if ttl <= 0 {
		return IssuedToken{}, errors.New("token TTL must be positive")
	}
	raw, err := s.randomString(32)
	if err != nil {
		return IssuedToken{}, err
	}
	now := s.now().UTC()
	token := EnrollmentToken{Hash: sha256.Sum256([]byte(raw)), Role: role, ExpiresAt: now.Add(ttl)}
	if err := s.store.SaveEnrollmentToken(ctx, token); err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Token: raw, Role: role, ExpiresAt: token.ExpiresAt}, nil
}

func (s *Service) Enroll(ctx context.Context, request EnrollRequest) (Device, error) {
	if strings.TrimSpace(request.Name) == "" || request.IdentityPublicKey == "" || request.WireGuardPublicKey == "" {
		return Device{}, errors.New("name and public keys are required")
	}
	now := s.now().UTC()
	role, err := s.store.ConsumeEnrollmentToken(ctx, sha256.Sum256([]byte(request.Token)), now)
	if err != nil {
		return Device{}, ErrInvalidEnrollmentToken
	}
	id, err := s.randomString(16)
	if err != nil {
		return Device{}, err
	}
	credential, err := s.randomString(32)
	if err != nil {
		return Device{}, err
	}
	device := Device{ID: id, Name: request.Name, Role: role, Status: StatusActive, IdentityPublicKey: request.IdentityPublicKey, WireGuardPublicKey: request.WireGuardPublicKey, CreatedAt: now, Credential: credential, CredentialHash: sha256.Sum256([]byte(credential))}
	if err := s.store.SaveDevice(ctx, device); err != nil {
		return Device{}, err
	}
	if s.publisher != nil {
		// GoChannel events are side effects, not part of the enrollment
		// transaction. A future durable broker should use an outbox here.
		_ = s.publisher.Publish(ctx, Event{Type: "device.enrolled", AggregateID: device.ID, OccurredAt: now})
	}
	return device, nil
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	now := s.now().UTC()
	if err := s.store.RevokeDevice(ctx, id, now); err != nil {
		return err
	}
	if s.publisher != nil {
		_ = s.publisher.Publish(ctx, Event{Type: "device.revoked", AggregateID: id, OccurredAt: now})
	}
	return nil
}
func (s *Service) List(ctx context.Context) ([]Device, error) { return s.store.ListDevices(ctx) }
func (s *Service) Authenticate(ctx context.Context, credential string) (Device, error) {
	if credential == "" {
		return Device{}, ErrDeviceNotFound
	}

	return s.store.AuthenticateCredential(ctx, sha256.Sum256([]byte(credential)), s.now().UTC())
}
func (s *Service) randomString(size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(s.random, b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
