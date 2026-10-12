package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/controlclient"
	"github.com/StasOkhrym/homeharbor/internal/invite"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

// InviteEnrollment pins root and network authority supplied by the caller.
// StatePath is mandatory: existing private keys are saved before transmission.
type InviteEnrollment struct {
	ControlURL    string
	InviteLink    string
	Code          string
	DeviceID      string
	StatePath     string
	RootPublicKey ed25519.PublicKey
	NetworkID     string
	PollInterval  time.Duration
	OnStage       func(InviteStage)
}

// InviteStage reports protocol progress without implying that network policy
// has been applied. Application belongs to the normal client runtime.
type InviteStage string

const (
	InvitePending  InviteStage = "pending"
	InviteApproved InviteStage = "approved"
	InviteClaimed  InviteStage = "claimed"
)

var inviteCanonical = func() cbor.EncMode {
	m, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

func strictInviteBytes(raw string, n int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || n >= 0 && len(b) != n || base64.RawURLEncoding.EncodeToString(b) != raw {
		return nil, invite.ErrInvalidProof
	}

	return b, nil
}

// PrepareInviteProof consumes fragment authority locally. Only signed public
// proof material is returned; the code and private keys never enter HTTP JSON.
func PrepareInviteProof(
	p InviteEnrollment,
	state State,
	now time.Time,
) (invite.SignedPermit, invite.Proof, error) {
	if err := state.Validate(); err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	if p.DeviceID == "" || state.DeviceID != "" && state.DeviceID != p.DeviceID ||
		len(p.Code) != 8 {
		return invite.SignedPermit{}, invite.Proof{}, invite.ErrInvalidProof
	}

	for _, c := range p.Code {
		if c < '0' || c > '9' {
			return invite.SignedPermit{}, invite.Proof{}, invite.ErrInvalidProof
		}
	}

	u, err := url.Parse(p.InviteLink)
	if err != nil {
		return invite.SignedPermit{}, invite.Proof{}, invite.ErrInvalidPermit
	}

	fragment, err := url.ParseQuery(u.Fragment)
	if err != nil || len(fragment) != 2 || len(fragment["permit"]) != 1 ||
		len(fragment["invite_key"]) != 1 {
		return invite.SignedPermit{}, invite.Proof{}, invite.ErrInvalidPermit
	}

	encoded, err := strictInviteBytes(fragment.Get("permit"), -1)
	if err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	var signed invite.SignedPermit

	if err := cbor.Unmarshal(encoded, &signed); err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	canonical, err := inviteCanonical.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return invite.SignedPermit{}, invite.Proof{}, invite.ErrInvalidPermit
	}

	if err = invite.VerifyPermit(signed, p.RootPublicKey, p.NetworkID, now); err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	var permit invite.Permit

	if err = cbor.Unmarshal(signed.Payload, &permit); err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	inviteSecret, err := strictInviteBytes(fragment.Get("invite_key"), ed25519.PrivateKeySize)
	if err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	invitePrivate := ed25519.PrivateKey(inviteSecret)
	if !bytes.Equal(invitePrivate.Public().(ed25519.PublicKey), permit.InvitePublic) {
		return invite.SignedPermit{}, invite.Proof{}, invite.ErrInvalidPermit
	}
	// Verify the complete private-key representation, including its seed half.
	if !bytes.Equal(ed25519.NewKeyFromSeed(invitePrivate.Seed()), invitePrivate) {
		return invite.SignedPermit{}, invite.Proof{}, invite.ErrInvalidPermit
	}

	deviceSecret, err := strictInviteBytes(state.IdentityPrivateKey, ed25519.PrivateKeySize)
	if err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	devicePrivate := ed25519.PrivateKey(deviceSecret)
	if !bytes.Equal(ed25519.NewKeyFromSeed(devicePrivate.Seed()), devicePrivate) {
		return invite.SignedPermit{}, invite.Proof{}, invite.ErrInvalidProof
	}

	wg, err := wgtypes.ParseKey(state.WireGuard.PublicKey)
	if err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	digest := sha256.Sum256(append([]byte("homeharbor/invite-code/v1\x00"), []byte(p.Code)...))
	proof := invite.Proof{
		Version:            invite.Version,
		InviteID:           permit.InviteID,
		DeviceID:           p.DeviceID,
		DevicePublicKey:    devicePrivate.Public().(ed25519.PublicKey),
		WireGuardPublicKey: bytes.Clone(wg[:]),
		CodeDigest:         bytes.Clone(digest[:]),
	}
	payload, err := inviteCanonical.Marshal(struct {
		Version            uint16 `cbor:"version"`
		InviteID           string `cbor:"invite_id"`
		DeviceID           string `cbor:"device_id"`
		DevicePublicKey    []byte `cbor:"device_public_key"`
		WireGuardPublicKey []byte `cbor:"wireguard_public_key"`
		CodeDigest         []byte `cbor:"code_digest"`
	}{proof.Version, proof.InviteID, proof.DeviceID, proof.DevicePublicKey, proof.WireGuardPublicKey, proof.CodeDigest})
	if err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	message := append([]byte("homeharbor/invite-proof/v1\x00"), payload...)
	proof.Signature = ed25519.Sign(invitePrivate, message)
	proof.DeviceSignature = ed25519.Sign(devicePrivate, message)

	if err = invite.VerifyProof(signed, proof, permit.ProfileID, now); err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}

	return signed, proof, nil
}

func activationOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != "" {
		return "", errors.New("control URL must be an origin")
	}
	if u.Scheme == "https" ||
		u.Scheme == "http" &&
			(u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1") {
		return strings.TrimRight(raw, "/"), nil
	}

	return "", errors.New("control URL must use HTTPS or local HTTP")
}

// EnrollByInvite submits the proof, polls until approval appears in signed
// topology, then claims and atomically saves a credential using existing State
// keys. Lost claim responses are recovered with a fresh challenge/credential.
// Context cancellation bounds polling; a caller may retry with the same state.
func EnrollByInvite(
	ctx context.Context,
	httpClient *http.Client,
	p InviteEnrollment,
	state *State,
) error {
	return enrollByInvite(ctx, httpClient, p, state, func(current State) error {
		return current.Save(p.StatePath)
	})
}

// EnrollByInviteFrom keeps the caller's lifetime state lock across proof,
// approval polling and credential persistence.
func EnrollByInviteFrom(
	ctx context.Context,
	httpClient *http.Client,
	p InviteEnrollment,
	state *State,
	store *localstate.Store,
) error {
	if store == nil {
		return errors.New("state store is required")
	}

	return enrollByInvite(ctx, httpClient, p, state, func(current State) error {
		return current.SaveTo(store)
	})
}

func enrollByInvite(
	ctx context.Context,
	httpClient *http.Client,
	p InviteEnrollment,
	state *State,
	save func(State) error,
) error {
	if state == nil || p.StatePath == "" {
		return errors.New("state and state path are required")
	}
	base, err := activationOrigin(p.ControlURL)
	if err != nil {
		return err
	}
	permit, proof, err := PrepareInviteProof(p, *state, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := save(*state); err != nil {
		return err
	}
	client, err := controlclient.ForEndpoint(base, httpClient)
	if err != nil {
		return err
	}
	if err := client.SubmitInviteProof(ctx, permit, proof); err != nil {
		return fmt.Errorf("submit invite proof: %w", err)
	}
	if p.OnStage != nil {
		p.OnStage(InvitePending)
	}
	interval := p.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	private, err := strictInviteBytes(state.IdentityPrivateKey, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	approvedReported := false
	for {
		challenge, err := client.Challenge(ctx, proof.InviteID)
		if err == nil {
			if challenge.InviteID != proof.InviteID || challenge.DeviceID != p.DeviceID ||
				challenge.NetworkID != p.NetworkID ||
				challenge.ExpiresAt <= time.Now().Unix() ||
				challenge.ExpiresAt > time.Now().Add(protocol.ClaimTTL).Unix() {
				return protocol.ErrInvalidClaim
			}
			if p.OnStage != nil && !approvedReported {
				p.OnStage(InviteApproved)
				approvedReported = true
			}
			signed, signErr := protocol.SignClaim(challenge, ed25519.PrivateKey(private))
			if signErr != nil {
				return signErr
			}
			d, claimErr := client.Claim(ctx, proof.InviteID, signed)
			if claimErr == nil {
				if d.CredentialExpiresAt.IsZero() || d.ID != p.DeviceID || d.Status != "active" ||
					d.Role != "client" ||
					d.IdentityPublicKey != state.IdentityPublicKey ||
					d.WireGuardPublicKey != state.WireGuard.PublicKey {
					return errors.New("claim returned a different device identity")
				}
				if _, err := strictInviteBytes(d.Credential, 32); err != nil {
					return errors.New("invalid device credential")
				}
				updated := *state
				updated.DeviceID = d.ID
				updated.DeviceCredential = d.Credential
				updated.CredentialExpiresAt = d.CredentialExpiresAt
				if err := save(updated); err != nil {
					return err
				}
				*state = updated
				if p.OnStage != nil {
					p.OnStage(InviteClaimed)
				}
				return nil
			}
			err = claimErr
		}
		var status *controlclient.StatusError
		if errors.As(err, &status) && status.StatusCode != http.StatusConflict &&
			status.StatusCode != http.StatusServiceUnavailable && status.StatusCode != http.StatusTooManyRequests {
			return fmt.Errorf("activate invite: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
