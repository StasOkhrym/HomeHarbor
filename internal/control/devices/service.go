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
	"unicode/utf8"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

const maxDeviceNameBytes = 128

// CredentialTTL limits the useful lifetime of a bearer credential. Clients
// rotate before expiry, so compromise has a bounded window without forcing a
// user through enrollment again.
const CredentialTTL = 15 * time.Minute

var (
	ErrInvalidEnrollmentToken = errors.New("invalid or expired enrollment token")
	ErrInvalidTokenRequest    = errors.New("invalid enrollment token request")
	ErrInvalidEnrollment      = errors.New("invalid enrollment request")
	ErrDeviceNotFound         = errors.New("device not found")
	ErrDeviceConflict         = errors.New("device identity already exists")
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

type Repository interface {
	EnrollmentPort
	SaveEnrollmentToken(context.Context, EnrollmentToken) error
	ConsumeEnrollmentToken(context.Context, [32]byte, time.Time) (Role, error)
	SaveDevice(context.Context, Device) error
	Device(context.Context, string) (Device, error)
	ListDevices(context.Context) ([]Device, error)
	RevokeDevice(context.Context, string, time.Time) error
	AuthenticateCredential(context.Context, [32]byte, time.Time) (Device, error)
	RotateCredential(context.Context, string, [32]byte, [32]byte, time.Time, time.Time) error
}

// EnrollmentPort is required: token consumption and device persistence must
// succeed or roll back together. Services never emulate this with two writes.
type EnrollmentPort interface {
	Enroll(context.Context, [32]byte, time.Time, Device) (Role, error)
}

type Service struct {
	store       Repository
	now         func() time.Time
	random      io.Reader
	publication PublicationStrategy
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
	return WithPublicationStrategy(InProcessPublication{Publisher: publisher})
}

func NewService(store Repository, now func() time.Time, random io.Reader, options ...Option) *Service {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	service := &Service{store: store, now: now, random: random, publication: TransactionalOutbox{}}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) IssueEnrollmentToken(ctx context.Context, role Role, ttl time.Duration) (IssuedToken, error) {
	if role != RoleClient && role != RoleGateway {
		return IssuedToken{}, fmt.Errorf("%w: unsupported role", ErrInvalidTokenRequest)
	}
	if ttl <= 0 {
		return IssuedToken{}, fmt.Errorf("%w: token TTL must be positive", ErrInvalidTokenRequest)
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
	if err := validateEnrollmentRequest(request); err != nil {
		return Device{}, err
	}
	now := s.now().UTC()
	id, err := s.randomString(16)
	if err != nil {
		return Device{}, err
	}
	credential, err := s.randomString(32)
	if err != nil {
		return Device{}, err
	}
	device := Device{
		ID:                 id,
		Name:               request.Name,
		Status:             StatusActive,
		IdentityPublicKey:  request.IdentityPublicKey,
		WireGuardPublicKey: request.WireGuardPublicKey,
		CreatedAt:          now,
		Credential:         credential,
		CredentialHash:     sha256.Sum256([]byte(credential)),
	}
	role, err := s.store.Enroll(ctx, sha256.Sum256([]byte(request.Token)), now, device)
	if err != nil {
		return Device{}, err
	}
	device.Role = role
	if err = s.publication.AfterCommit(
		ctx,
		Event{Type: "device.enrolled", AggregateID: device.ID, OccurredAt: now},
	); err != nil {
		return Device{}, err
	}
	return device, nil
}

// validateEnrollmentRequest is the last trust-boundary check before public
// identity material is persisted and later copied into signed topology state.
// Accepting an arbitrary string here would let a malformed device poison peer
// reconciliation or make two textual encodings refer to the same key.
func validateEnrollmentRequest(request EnrollRequest) error {
	name := strings.TrimSpace(request.Name)
	if name == "" || name != request.Name || len(name) > maxDeviceNameBytes || !utf8.ValidString(name) {
		return fmt.Errorf(
			"%w: device name must be 1-%d printable UTF-8 bytes without surrounding whitespace",
			ErrInvalidEnrollment,
			maxDeviceNameBytes,
		)
	}
	for _, character := range name {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%w: device name contains a control character", ErrInvalidEnrollment)
		}
	}
	identity, err := base64.RawURLEncoding.DecodeString(request.IdentityPublicKey)
	if err != nil || len(identity) != 32 ||
		base64.RawURLEncoding.EncodeToString(identity) != request.IdentityPublicKey {
		return fmt.Errorf("%w: identity public key must be canonical base64url Ed25519 bytes", ErrInvalidEnrollment)
	}
	wireGuard, err := wgtypes.ParseKey(request.WireGuardPublicKey)
	if err != nil || wireGuard == (wgtypes.Key{}) || wireGuard.String() != request.WireGuardPublicKey {
		return fmt.Errorf("%w: WireGuard public key is invalid", ErrInvalidEnrollment)
	}
	if strings.TrimSpace(request.Token) == "" {
		return fmt.Errorf("%w: enrollment token is required", ErrInvalidEnrollment)
	}
	return nil
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	now := s.now().UTC()
	if err := s.store.RevokeDevice(ctx, id, now); err != nil {
		return err
	}
	return s.publication.AfterCommit(ctx, Event{Type: "device.revoked", AggregateID: id, OccurredAt: now})
}

// Device returns the current public metadata for an active or revoked device.
// Callers that authorize a new connection must still inspect Status rather than
// treating existence as permission to connect.
func (s *Service) Device(ctx context.Context, id string) (Device, error) {
	if strings.TrimSpace(id) == "" {
		return Device{}, ErrDeviceNotFound
	}

	return s.store.Device(ctx, id)
}

func (s *Service) List(ctx context.Context) ([]Device, error) { return s.store.ListDevices(ctx) }
func (s *Service) Authenticate(ctx context.Context, credential string) (Device, error) {
	if credential == "" {
		return Device{}, ErrDeviceNotFound
	}

	return s.store.AuthenticateCredential(ctx, sha256.Sum256([]byte(credential)), s.now().UTC())
}

// RotateCredential atomically replaces a still-valid credential. The old hash
// is part of the update predicate, preventing two concurrent refreshes from
// both succeeding with the same bearer credential.
func (s *Service) RotateCredential(ctx context.Context, deviceID, credential string) (string, error) {
	if strings.TrimSpace(deviceID) == "" || credential == "" {
		return "", ErrDeviceNotFound
	}
	newCredential, err := s.randomString(32)
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	if err := s.store.RotateCredential(
		ctx,
		deviceID,
		sha256.Sum256([]byte(credential)),
		sha256.Sum256([]byte(newCredential)),
		now,
		now.Add(CredentialTTL),
	); err != nil {
		return "", err
	}
	return newCredential, nil
}

func (s *Service) randomString(size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(s.random, b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
