package invites

import (
	"context"
	"crypto/ed25519"
	"errors"
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
)

type Record struct {
	InviteID     string              `json:"invite_id"`
	ProfileID    string              `json:"profile_id"`
	DeviceID     string              `json:"device_id"`
	DevicePublic []byte              `json:"device_public_key"`
	Permit       invite.SignedPermit `json:"permit"`
	Proof        invite.Proof        `json:"proof"`
	Status       Status              `json:"status"`
	CreatedAt    time.Time           `json:"created_at"`
	ApprovedAt   *time.Time          `json:"approved_at,omitempty"`
}

type Store interface {
	Save(context.Context, Record) error
	Get(context.Context, string) (Record, error)
	Approve(context.Context, string, time.Time) (Record, error)
}

type Service struct {
	store     Store
	root      ed25519.PublicKey
	networkID string
	now       func() time.Time
}

func NewService(store Store, root ed25519.PublicKey, networkID string, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, root: append(ed25519.PublicKey(nil), root...), networkID: networkID, now: now}
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
	return s.store.Save(ctx, Record{InviteID: proof.InviteID, ProfileID: profileID, DeviceID: proof.DeviceID, DevicePublic: append([]byte(nil), proof.DevicePublicKey...), Permit: permit, Proof: proof, Status: StatusPending, CreatedAt: now})
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
func (s *Service) ApproveSigned(ctx context.Context, signed invite.SignedApproval) (Record, error) {
	record, err := s.store.Get(ctx, approvalInviteID(signed))
	if err != nil {
		return Record{}, err
	}
	if record.Status != StatusPending {
		return Record{}, ErrInviteConsumed
	}
	expected := invite.Approval{Version: invite.Version, InviteID: record.InviteID, ProfileID: record.ProfileID, DeviceID: record.DeviceID, DevicePublicKey: record.DevicePublic}
	if err := invite.VerifyApproval(signed, s.root, expected); err != nil {
		return Record{}, err
	}
	return s.store.Approve(ctx, record.InviteID, s.now().UTC())
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
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{records: make(map[string]Record)} }

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
