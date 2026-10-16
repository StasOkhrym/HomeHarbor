// Package workflows coordinates narrow use cases across module boundaries.
// No workflow exposes a generic database or writes module-owned tables.
package workflows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/invites"
	"github.com/StasOkhrym/homeharbor/internal/invite"
	"github.com/StasOkhrym/homeharbor/internal/platform/redissecurity"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

const (
	claimPurpose = "activation-claim-v1"
)

var ErrNotReady = errors.New("activation is not in the signed snapshot")

type (
	InviteReader interface {
		Get(context.Context, string) (invites.Record, error)
	}
	SnapshotReader interface {
		Latest(context.Context) (snapshot.Envelope, error)
	}
	ChallengeRepository interface {
		PutChallenge(context.Context, string, string, []byte, time.Duration) error
		ConsumeChallenge(context.Context, string, string) ([]byte, error)
	}
)

type InviteTransaction interface {
	Lock(context.Context, string) (invites.Record, error)
	Approve(context.Context, string, time.Time) (invites.Record, error)
}
type DeviceTransaction interface {
	CreateIdentity(context.Context, devices.Device) error
	ReplaceCredential(
		context.Context,
		string,
		[32]byte,
		time.Time,
		time.Time,
	) (devices.Device, error)
}
type (
	ProfileTransaction interface {
		AddDevice(context.Context, string, string) error
	}
	Outbox interface {
		Append(context.Context, devices.Event) error
	}
	ActivationTransaction struct {
		Invites  InviteTransaction
		Devices  DeviceTransaction
		Profiles ProfileTransaction
		Outbox   Outbox
	}
)

// ActivationUnitOfWork binds all four ports to a single transaction. The
// callback must not retain the ports; callback failure rolls every write back.
type ActivationUnitOfWork interface {
	WithinActivation(context.Context, func(ActivationTransaction) error) error
}
type Activation struct {
	uow           ActivationUnitOfWork
	invites       InviteReader
	snapshots     SnapshotReader
	challenges    ChallengeRepository
	root          ed25519.PublicKey
	network       string
	now           func() time.Time
	random        io.Reader
	claimTTL      time.Duration
	credentialTTL time.Duration
}

// ActivationOption supplies dependencies owned by the application boundary.
type ActivationOption func(*Activation)

// WithLifetimes uses validated issuance limits; protocol.ClaimTTL remains the maximum
// lifetime accepted by existing clients, not a negotiated trust relaxation.
func WithLifetimes(claim, credential time.Duration) ActivationOption {
	return func(a *Activation) { a.claimTTL, a.credentialTTL = claim, credential }
}

func NewActivation(
	uow ActivationUnitOfWork,
	records InviteReader,
	snapshots SnapshotReader,
	challenges ChallengeRepository,
	root ed25519.PublicKey,
	network string,
	now func() time.Time,
	random io.Reader,
	options ...ActivationOption,
) *Activation {
	if now == nil {
		now = time.Now
	}

	if random == nil {
		random = rand.Reader
	}

	a := &Activation{
		uow:           uow,
		invites:       records,
		snapshots:     snapshots,
		challenges:    challenges,
		root:          bytes.Clone(root),
		network:       network,
		now:           now,
		random:        random,
		claimTTL:      protocol.ClaimTTL,
		credentialTTL: devices.CredentialTTL,
	}
	for _, option := range options {
		option(a)
	}

	return a
}

func (a *Activation) ApproveSigned(
	ctx context.Context,
	signed invite.SignedApproval,
) (invites.ApprovalResult, error) {
	if a.uow == nil {
		return invites.ApprovalResult{}, errors.New("activation unit of work is required")
	}

	var approval invite.Approval
	if cbor.Unmarshal(signed.Payload, &approval) != nil || approval.InviteID == "" {
		return invites.ApprovalResult{}, invite.ErrInvalidApproval
	}

	var result invites.ApprovalResult

	err := a.uow.WithinActivation(ctx, func(tx ActivationTransaction) error {
		r, err := tx.Invites.Lock(ctx, approval.InviteID)
		if err != nil {
			return err
		}

		expected := invite.Approval{
			Version:            invite.Version,
			InviteID:           r.InviteID,
			ProfileID:          r.ProfileID,
			DeviceID:           r.DeviceID,
			DevicePublicKey:    r.DevicePublic,
			WireGuardPublicKey: r.WireGuardPublicKey,
		}
		// Verify exact diff even on an approved retry: approval is not a bypass.
		if err = invite.VerifyApproval(signed, a.root, expected); err != nil {
			return err
		}

		facts := audit.FromContext(ctx)
		facts.ActorType, facts.ActorID = "companion", base64.RawURLEncoding.EncodeToString(a.root)
		facts.ActorName = "Network companion"
		facts.Authentication = "companion_signature"
		eventContext := audit.WithContext(ctx, facts)
		if r.Status == invites.StatusBlocked {
			return invites.ErrInviteBlocked
		}
		if r.Status != invites.StatusPending && r.Status != invites.StatusApproved {
			return invites.ErrInviteConsumed
		}

		if r.Status == invites.StatusPending {
			now := a.now().UTC()
			if err = invite.VerifyPermit(r.Permit, a.root, a.network, now); err != nil {
				return err
			}

			if err = invite.VerifyProof(r.Permit, r.Proof, r.ProfileID, now); err != nil {
				return err
			}

			if len(r.WireGuardPublicKey) != 32 {
				return invite.ErrInvalidApproval
			}

			var wg wgtypes.Key
			copy(wg[:], r.WireGuardPublicKey)
			d := devices.Device{
				ID:                 r.DeviceID,
				Name:               r.DeviceID,
				Role:               devices.RoleClient,
				Status:             devices.StatusActive,
				IdentityPublicKey:  base64.RawURLEncoding.EncodeToString(r.DevicePublic),
				WireGuardPublicKey: wg.String(),
				CreatedAt:          now,
			}
			if err = tx.Devices.CreateIdentity(ctx, d); err != nil {
				return err
			}

			if err = tx.Profiles.AddDevice(ctx, r.ProfileID, r.DeviceID); err != nil {
				return err
			}

			if r, err = tx.Invites.Approve(ctx, r.InviteID, now); err != nil {
				return err
			}

			for _, e := range []devices.Event{{Type: "device.enrolled", AggregateID: r.DeviceID, OccurredAt: now}, {Type: "invite.approved", AggregateID: r.InviteID, OccurredAt: now}} {
				if err = tx.Outbox.Append(eventContext, e); err != nil {
					return err
				}
			}
		}

		result = invites.ApprovalResult{
			Record:    r,
			InviteID:  r.InviteID,
			DeviceID:  r.DeviceID,
			ProfileID: r.ProfileID,
			Status:    r.Status,
		}

		return nil
	})
	if err != nil {
		return invites.ApprovalResult{}, err
	}

	return result, nil
}

type ClaimResult struct {
	Device devices.Device `json:"device"`
}

func (a *Activation) ready(ctx context.Context, id string) (invites.Record, error) {
	if a.invites == nil || a.snapshots == nil || len(a.root) != ed25519.PublicKeySize ||
		a.network == "" {
		return invites.Record{}, ErrNotReady
	}

	r, err := a.invites.Get(ctx, id)
	if err != nil {
		return invites.Record{}, err
	}
	if r.Status != invites.StatusApproved || len(r.DevicePublic) != 32 ||
		len(r.WireGuardPublicKey) != 32 {
		return invites.Record{}, ErrNotReady
	}

	envelope, err := a.snapshots.Latest(ctx)
	if err != nil {
		return invites.Record{}, err
	}

	value, err := snapshot.Verify(envelope, a.root, a.network)
	if err != nil {
		return invites.Record{}, ErrNotReady
	}

	var wg wgtypes.Key
	copy(wg[:], r.WireGuardPublicKey)
	matching := false
	for _, d := range value.Devices {
		if d.ID == r.DeviceID && d.Role == "client" &&
			d.IdentityPublicKey == base64.RawURLEncoding.EncodeToString(r.DevicePublic) &&
			d.WireGuardPublicKey == wg.String() {
			matching = true
		}
	}

	if matching {
		for _, p := range value.Profiles {
			if p.ID == r.ProfileID && slices.Contains(p.DeviceIDs, r.DeviceID) {
				return r, nil
			}
		}
	}

	return invites.Record{}, ErrNotReady
}

func (a *Activation) Challenge(ctx context.Context, id string) (protocol.ClaimChallenge, error) {
	r, err := a.ready(ctx, id)
	if err != nil {
		return protocol.ClaimChallenge{}, err
	}
	if a.challenges == nil {
		return protocol.ClaimChallenge{}, errors.New("shared challenge repository is required")
	}

	var nonce [32]byte

	if _, err = io.ReadFull(a.random, nonce[:]); err != nil {
		return protocol.ClaimChallenge{}, err
	}

	c := protocol.ClaimChallenge{
		Version:   1,
		NetworkID: a.network,
		InviteID:  id,
		DeviceID:  r.DeviceID,
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce[:]),
		ExpiresAt: a.now().UTC().Add(a.claimTTL).Unix(),
	}
	p, err := protocol.ClaimPayload(c)
	if err != nil {
		return protocol.ClaimChallenge{}, err
	}

	if err = a.challenges.PutChallenge(ctx, claimPurpose, c.Nonce, p, a.claimTTL); err != nil {
		return protocol.ClaimChallenge{}, err
	}

	return c, nil
}

func (a *Activation) Claim(
	ctx context.Context,
	id string,
	proof protocol.ClaimProof,
) (ClaimResult, error) {
	r, err := a.ready(ctx, id)
	if err != nil {
		return ClaimResult{}, err
	}

	c := proof.Challenge
	if c.NetworkID != a.network || c.InviteID != id || c.DeviceID != r.DeviceID ||
		a.now().UTC().Unix() >= c.ExpiresAt ||
		c.ExpiresAt > a.now().UTC().Add(a.claimTTL).Unix() {
		return ClaimResult{}, protocol.ErrInvalidClaim
	}

	p, err := protocol.ClaimPayload(c)
	if err != nil {
		return ClaimResult{}, protocol.ErrInvalidClaim
	}
	if protocol.VerifyClaim(proof, r.DevicePublic) != nil {
		return ClaimResult{}, protocol.ErrInvalidClaim
	}
	if a.challenges == nil {
		return ClaimResult{}, errors.New("shared challenge repository is required")
	}

	stored, err := a.challenges.ConsumeChallenge(ctx, claimPurpose, c.Nonce)
	if errors.Is(err, redissecurity.ErrChallengeMissing) {
		return ClaimResult{}, protocol.ErrInvalidClaim
	}
	if err != nil {
		return ClaimResult{}, err
	}
	if !bytes.Equal(stored, p) {
		return ClaimResult{}, protocol.ErrInvalidClaim
	}
	if a.uow == nil {
		return ClaimResult{}, errors.New("activation unit of work is required")
	}

	var secret [32]byte

	if _, err = io.ReadFull(a.random, secret[:]); err != nil {
		return ClaimResult{}, err
	}

	credential := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(credential))
	var d devices.Device

	err = a.uow.WithinActivation(ctx, func(tx ActivationTransaction) error {
		current, lockErr := tx.Invites.Lock(ctx, id)
		if lockErr != nil {
			return lockErr
		}
		if current.Status != invites.StatusApproved || current.DeviceID != r.DeviceID ||
			current.ProfileID != r.ProfileID ||
			!bytes.Equal(current.DevicePublic, r.DevicePublic) ||
			!bytes.Equal(current.WireGuardPublicKey, r.WireGuardPublicKey) {
			return protocol.ErrInvalidClaim
		}

		now := a.now().UTC()
		d, lockErr = tx.Devices.ReplaceCredential(
			ctx,
			r.DeviceID,
			hash,
			now,
			now.Add(a.credentialTTL),
		)
		d.CredentialExpiresAt = now.Add(a.credentialTTL)
		if lockErr != nil {
			return lockErr
		}

		var wg wgtypes.Key
		copy(wg[:], r.WireGuardPublicKey)
		if d.IdentityPublicKey != base64.RawURLEncoding.EncodeToString(r.DevicePublic) ||
			d.WireGuardPublicKey != wg.String() ||
			d.Role != devices.RoleClient {
			return protocol.ErrInvalidClaim
		}

		return tx.Outbox.Append(
			ctx,
			devices.Event{
				Type:        "device.credential_claimed",
				AggregateID: r.DeviceID,
				OccurredAt:  now,
			},
		)
	})
	if err != nil {
		return ClaimResult{}, err
	}

	d.Credential = credential
	d.CredentialHash = [32]byte{}

	return ClaimResult{Device: d}, nil
}
