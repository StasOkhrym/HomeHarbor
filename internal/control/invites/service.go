package invites

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/sokhrym/go-tunnels/internal/invite"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
)

var (
	ErrInviteNotFound = errors.New("invite not found")
	ErrInviteConsumed = errors.New("invite already consumed")
	ErrInvalidCode    = errors.New("invalid invite code")
	ErrDeviceConflict = errors.New("device already exists")
)

type Record struct {
	InviteID           string              `json:"invite_id"`
	ProfileID          string              `json:"profile_id"`
	DeviceID           string              `json:"device_id"`
	DevicePublic       []byte              `json:"device_public_key"`
	WireGuardPublicKey []byte              `json:"wireguard_public_key"`
	Permit             invite.SignedPermit `json:"permit"`
	Proof              invite.Proof        `json:"proof"`
	Status             Status              `json:"status"`
	CreatedAt          time.Time           `json:"created_at"`
	ApprovedAt         *time.Time          `json:"approved_at,omitempty"`
}

type Store interface {
	Save(context.Context, Record) error
	Get(context.Context, string) (Record, error)
	Approve(context.Context, string, time.Time) (Record, error)
}

// DeviceActivation contains public identity material and a newly issued
// credential. The store persists only CredentialHash, so plaintext credentials
// cannot be recovered after the one-time activation response.
type DeviceActivation struct {
	ID                 string
	Name               string
	Role               string
	IdentityPublicKey  string
	WireGuardPublicKey string
	Credential         string
	CredentialHash     [32]byte
	CreatedAt          time.Time
}

// ActivatedDevice is the public device bootstrap returned exactly once after
// activation. Credential is omitted from all later device reads.
type ActivatedDevice struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Role               string    `json:"role"`
	Status             string    `json:"status"`
	IdentityPublicKey  string    `json:"identity_public_key"`
	WireGuardPublicKey string    `json:"wireguard_public_key"`
	CreatedAt          time.Time `json:"created_at"`
	Credential         string    `json:"credential,omitempty"`
}

// ActivationResult is the one-time response returned after a trusted approval.
// Record stays internal to the application boundary; only Device is serialized
// by the HTTP handler so permit and proof material is not echoed to clients.
type ActivationResult struct {
	Record Record          `json:"-"`
	Device ActivatedDevice `json:"device"`
}

// Activator owns the transaction that changes invite, device, credential and
// profile membership together. It is deliberately narrower than a repository.
type Activator interface {
	Activate(context.Context, Record, DeviceActivation, time.Time) (Record, error)
}

type Service struct {
	store     Store
	root      ed25519.PublicKey
	networkID string
	now       func() time.Time
	random    io.Reader
	activator Activator
}

// Option configures optional invite-service behavior at the composition root.
type Option func(*Service)

func WithActivator(activator Activator) Option {
	return func(service *Service) { service.activator = activator }
}

func WithRandom(random io.Reader) Option {
	return func(service *Service) {
		if random != nil {
			service.random = random
		}
	}
}

func NewService(store Store, root ed25519.PublicKey, networkID string, now func() time.Time, options ...Option) *Service {
	if now == nil {
		now = time.Now
	}
	service := &Service{store: store, root: append(ed25519.PublicKey(nil), root...), networkID: networkID, now: now, random: rand.Reader}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) SubmitProof(ctx context.Context, permit invite.SignedPermit, proof invite.Proof) error {
	now := s.now().UTC()
	if err := invite.VerifyPermit(permit, s.root, s.networkID, now); err != nil {
		return err
	}
	profileID, err := invite.PermitProfile(permit)
	if err != nil {
		return err
	}
	if err = invite.VerifyProof(permit, proof, profileID, now); err != nil {
		return err
	}
	return s.store.Save(ctx, Record{InviteID: proof.InviteID, ProfileID: profileID, DeviceID: proof.DeviceID, DevicePublic: append([]byte(nil), proof.DevicePublicKey...), WireGuardPublicKey: append([]byte(nil), proof.WireGuardPublicKey...), Permit: permit, Proof: proof, Status: StatusPending, CreatedAt: now})
}

func (s *Service) Get(ctx context.Context, inviteID string) (Record, error) {
	return s.store.Get(ctx, inviteID)
}

func (s *Service) Approve(ctx context.Context, inviteID, code string) (Record, error) {
	record, err := s.store.Get(ctx, inviteID)
	if err != nil {
		return Record{}, err
	}
	if record.Status != StatusPending {
		return Record{}, ErrInviteConsumed
	}
	if err = invite.VerifyProofWithCode(record.Permit, record.Proof, record.ProfileID, code, s.now().UTC()); err != nil {
		return Record{}, ErrInvalidCode
	}
	return s.store.Approve(ctx, inviteID, s.now().UTC())
}

// ApproveSigned accepts only the companion's root-signed exact diff. The
// control plane verifies the pending record first, so a valid root signature
// cannot be replayed against another device or profile.
func (s *Service) ApproveSigned(ctx context.Context, signed invite.SignedApproval) (ActivationResult, error) {
	record, err := s.store.Get(ctx, approvalInviteID(signed))
	if err != nil {
		return ActivationResult{}, err
	}
	if record.Status != StatusPending {
		return ActivationResult{}, ErrInviteConsumed
	}
	expected := invite.Approval{Version: invite.Version, InviteID: record.InviteID, ProfileID: record.ProfileID, DeviceID: record.DeviceID, DevicePublicKey: record.DevicePublic, WireGuardPublicKey: record.WireGuardPublicKey}
	if err := invite.VerifyApproval(signed, s.root, expected); err != nil {
		return ActivationResult{}, err
	}
	if s.activator == nil {
		approved, approveErr := s.store.Approve(ctx, record.InviteID, s.now().UTC())
		return ActivationResult{Record: approved}, approveErr
	}
	credentialBytes := make([]byte, 32)
	if _, err := io.ReadFull(s.random, credentialBytes); err != nil {
		return ActivationResult{}, err
	}
	credential := base64.RawURLEncoding.EncodeToString(credentialBytes)
	activation := DeviceActivation{
		ID:                 record.DeviceID,
		Name:               record.DeviceID,
		Role:               "client",
		IdentityPublicKey:  base64.RawURLEncoding.EncodeToString(record.DevicePublic),
		WireGuardPublicKey: base64.RawURLEncoding.EncodeToString(record.WireGuardPublicKey),
		Credential:         credential,
		CredentialHash:     sha256.Sum256([]byte(credential)),
		CreatedAt:          s.now().UTC(),
	}
	approved, err := s.activator.Activate(ctx, record, activation, activation.CreatedAt)
	if err != nil {
		return ActivationResult{}, err
	}
	return ActivationResult{Record: approved, Device: ActivatedDevice{
		ID: activation.ID, Name: activation.Name, Role: activation.Role, Status: "active",
		IdentityPublicKey: activation.IdentityPublicKey, WireGuardPublicKey: activation.WireGuardPublicKey,
		CreatedAt: activation.CreatedAt, Credential: activation.Credential,
	}}, nil
}

func approvalInviteID(signed invite.SignedApproval) string {
	var approval invite.Approval
	if err := cbor.Unmarshal(signed.Payload, &approval); err != nil {
		return ""
	}
	return approval.InviteID
}

type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
	devices map[string]DeviceActivation
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record), devices: make(map[string]DeviceActivation)}
}

func (s *MemoryStore) Save(_ context.Context, record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.InviteID]; exists {
		return ErrInviteConsumed
	}
	s.records[record.InviteID] = record
	return nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, ErrInviteNotFound
	}
	return record, nil
}

func (s *MemoryStore) Approve(_ context.Context, id string, at time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, ErrInviteNotFound
	}
	if record.Status != StatusPending {
		return Record{}, ErrInviteConsumed
	}
	record.Status = StatusApproved
	record.ApprovedAt = &at
	s.records[id] = record
	return record, nil
}

func (s *MemoryStore) Activate(_ context.Context, record Record, device DeviceActivation, at time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[record.InviteID]
	if !ok {
		return Record{}, ErrInviteNotFound
	}
	if current.Status != StatusPending {
		return Record{}, ErrInviteConsumed
	}
	if _, exists := s.devices[device.ID]; exists {
		return Record{}, ErrDeviceConflict
	}
	current.Status = StatusApproved
	current.ApprovedAt = &at
	s.records[record.InviteID] = current
	device.Credential = ""
	s.devices[device.ID] = device
	return current, nil
}
