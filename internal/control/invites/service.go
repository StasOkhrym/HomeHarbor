package invites

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/invite"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusBlocked  Status = "blocked"
)

// MaxInvalidCodeAttempts is deliberately small because the invite code is
// only eight decimal digits and is entered through a separate channel. The
// store increments this counter atomically so concurrent approval workers
// cannot bypass the lockout.
const MaxInvalidCodeAttempts = 5

var (
	ErrInviteNotFound = errors.New("invite not found")
	ErrInviteConsumed = errors.New("invite already consumed")
	ErrInviteBlocked  = errors.New("invite is blocked after invalid code attempts")
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
	FailedCodeAttempts int                 `json:"failed_code_attempts"`
	BlockedAt          *time.Time          `json:"blocked_at,omitempty"`
}

type Repository interface {
	Save(context.Context, Record) error
	Get(context.Context, string) (Record, error)
	Approve(context.Context, string, time.Time) (Record, error)
	RecordInvalidCodeAttempt(context.Context, string, time.Time) error
}

// ApprovalResult contains public status only. Credentials belong exclusively
// to the device possession claim, never to companion approval.
type ApprovalResult struct {
	Record    Record `json:"-"`
	InviteID  string `json:"invite_id"`
	DeviceID  string `json:"device_id"`
	ProfileID string `json:"profile_id"`
	Status    Status `json:"status"`
}

type ApprovalWorkflow interface {
	ApproveSigned(context.Context, invite.SignedApproval) (ApprovalResult, error)
}

type Service struct {
	store     Repository
	root      ed25519.PublicKey
	networkID string
	now       func() time.Time
	random    io.Reader
	workflow  ApprovalWorkflow
}

// Option configures optional invite-service behavior at the composition root.
type Option func(*Service)

func WithApprovalWorkflow(workflow ApprovalWorkflow) Option {
	return func(service *Service) { service.workflow = workflow }
}

func WithRandom(random io.Reader) Option {
	return func(service *Service) {
		if random != nil {
			service.random = random
		}
	}
}

func NewService(
	store Repository,
	root ed25519.PublicKey,
	networkID string,
	now func() time.Time,
	options ...Option,
) *Service {
	if now == nil {
		now = time.Now
	}
	service := &Service{
		store:     store,
		root:      append(ed25519.PublicKey(nil), root...),
		networkID: networkID,
		now:       now,
		random:    rand.Reader,
	}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) SubmitProof(
	ctx context.Context,
	permit invite.SignedPermit,
	proof invite.Proof,
) error {
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

	return s.store.Save(
		ctx,
		Record{
			InviteID:           proof.InviteID,
			ProfileID:          profileID,
			DeviceID:           proof.DeviceID,
			DevicePublic:       append([]byte(nil), proof.DevicePublicKey...),
			WireGuardPublicKey: append([]byte(nil), proof.WireGuardPublicKey...),
			Permit:             permit,
			Proof:              proof,
			Status:             StatusPending,
			CreatedAt:          now,
		},
	)
}

func (s *Service) Get(ctx context.Context, inviteID string) (Record, error) {
	return s.store.Get(ctx, inviteID)
}

func (s *Service) Approve(ctx context.Context, inviteID, code string) (Record, error) {
	record, err := s.store.Get(ctx, inviteID)
	if err != nil {
		return Record{}, err
	}
	if record.Status == StatusBlocked {
		return Record{}, ErrInviteBlocked
	}
	if record.Status != StatusPending {
		return Record{}, ErrInviteConsumed
	}

	if err = invite.VerifyProofWithCode(
		record.Permit,
		record.Proof,
		record.ProfileID,
		code,
		s.now().UTC(),
	); err != nil {
		if recordErr := s.store.RecordInvalidCodeAttempt(
			ctx,
			inviteID,
			s.now().UTC(),
		); recordErr != nil {
			return Record{}, recordErr
		}

		return Record{}, ErrInvalidCode
	}

	return s.store.Approve(ctx, inviteID, s.now().UTC())
}

// ApproveSigned accepts only the companion's root-signed exact diff. The
// control plane verifies the pending record first, so a valid root signature
// cannot be replayed against another device or profile.
func (s *Service) ApproveSigned(
	ctx context.Context,
	signed invite.SignedApproval,
) (ApprovalResult, error) {
	if s.workflow == nil {
		return ApprovalResult{}, errors.New("invite approval workflow is required")
	}

	return s.workflow.ApproveSigned(ctx, signed)
}
