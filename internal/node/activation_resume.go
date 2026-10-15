package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/controlclient"
	"github.com/StasOkhrym/homeharbor/internal/invite"
)

// verifyApprovedResume does not extend permit lifetime. It authenticates an
// existing approval at its recorded time, bound to exactly the persisted keys.
// The current challenge/claim still requires root-signed topology inclusion and
// authoritative active-device checks on control; local network apply separately
// verifies signed topology. A new expired invite never enters this path.
func verifyApprovedResume(
	ctx context.Context,
	client *controlclient.Client,
	p InviteEnrollment,
	state State,
) error {
	if err := state.Validate(); err != nil {
		return err
	}

	if p.DeviceID == "" || state.DeviceID != "" && state.DeviceID != p.DeviceID ||
		len(p.RootPublicKey) != ed25519.PublicKeySize ||
		p.NetworkID == "" {
		return invite.ErrInvalidProof
	}

	record, err := client.Invite(ctx, p.ResumeInviteID)
	if err != nil {
		return err
	}

	public, err := base64.RawURLEncoding.Strict().DecodeString(state.IdentityPublicKey)
	if err != nil {
		return err
	}

	wg, err := wgtypes.ParseKey(state.WireGuard.PublicKey)
	if err != nil {
		return err
	}
	if record.InviteID != p.ResumeInviteID || record.Status != "approved" ||
		record.ApprovedAt == nil || record.ApprovedAt.IsZero() ||
		record.ApprovedAt.After(time.Now()) ||
		record.DeviceID != p.DeviceID || record.Proof.InviteID != record.InviteID ||
		record.Proof.DeviceID != p.DeviceID ||
		!bytes.Equal(record.DevicePublic, public) ||
		!bytes.Equal(record.WireGuardPublicKey, wg[:]) ||
		!bytes.Equal(record.Proof.DevicePublicKey, public) ||
		!bytes.Equal(record.Proof.WireGuardPublicKey, wg[:]) {
		return errors.New("invitation is not approved for this existing identity")
	}

	if err := invite.VerifyPermit(
		record.Permit,
		p.RootPublicKey,
		p.NetworkID,
		record.ApprovedAt.UTC(),
	); err != nil {
		return err
	}

	return invite.VerifyProof(
		record.Permit,
		record.Proof,
		record.ProfileID,
		record.ApprovedAt.UTC(),
	)
}
