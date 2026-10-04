package workflows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type RecoveryDevices interface {
	Device(context.Context, string) (devices.Device, error)
	RecoverCredential(context.Context, string, string) (protocol.CredentialLease, error)
}
type RecoveryChallenges interface {
	PutChallenge(context.Context, string, string, []byte, time.Duration) error
	ConsumeChallenge(context.Context, string, string) ([]byte, error)
}
type CredentialRecovery struct {
	devices    RecoveryDevices
	challenges RecoveryChallenges
	network    string
	now        func() time.Time
	random     io.Reader
}

func NewCredentialRecovery(
	d RecoveryDevices,
	c RecoveryChallenges,
	network string,
	now func() time.Time,
	random io.Reader,
) *CredentialRecovery {
	if now == nil {
		now = time.Now
	}

	if random == nil {
		random = rand.Reader
	}

	return &CredentialRecovery{d, c, network, now, random}
}

func (r *CredentialRecovery) Challenge(
	ctx context.Context,
	id string,
) (protocol.CredentialChallenge, error) {
	if strings.TrimSpace(id) != id || id == "" || len(id) > 128 || r.network == "" {
		return protocol.CredentialChallenge{}, protocol.ErrInvalidCredentialProof
	}
	if r.challenges == nil {
		return protocol.CredentialChallenge{}, errors.New("credential recovery unavailable")
	}

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(r.random, nonce); err != nil {
		return protocol.CredentialChallenge{}, err
	}

	c := protocol.CredentialChallenge{
		Version:   1,
		NetworkID: r.network,
		DeviceID:  id,
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
		ExpiresAt: r.now().Add(protocol.CredentialChallengeTTL).Unix(),
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return protocol.CredentialChallenge{}, err
	}

	if err = r.challenges.PutChallenge(
		ctx,
		"credential-recovery",
		c.Nonce,
		raw,
		protocol.CredentialChallengeTTL,
	); err != nil {
		return protocol.CredentialChallenge{}, err
	}

	return c, nil
}

func (r *CredentialRecovery) Recover(
	ctx context.Context,
	p protocol.CredentialProof,
) (protocol.CredentialLease, error) {
	invalid := protocol.ErrInvalidCredentialProof
	c := p.Challenge
	now := r.now()
	if c.NetworkID != r.network || c.ExpiresAt <= now.Unix() ||
		c.ExpiresAt > now.Add(protocol.CredentialChallengeTTL).Unix() {
		return protocol.CredentialLease{}, invalid
	}

	if _, err := c.SigningBytes(); err != nil {
		return protocol.CredentialLease{}, invalid
	}

	d, err := r.devices.Device(ctx, c.DeviceID)
	if err != nil || d.ID != c.DeviceID || d.Status != devices.StatusActive {
		return protocol.CredentialLease{}, invalid
	}

	public, err := base64.RawURLEncoding.Strict().DecodeString(d.IdentityPublicKey)
	if err != nil || base64.RawURLEncoding.EncodeToString(public) != d.IdentityPublicKey ||
		protocol.VerifyCredentialProof(p, ed25519.PublicKey(public)) != nil {
		return protocol.CredentialLease{}, invalid
	}
	if r.challenges == nil {
		return protocol.CredentialLease{}, errors.New("credential recovery unavailable")
	}
	if c.ExpiresAt <= r.now().Unix() {
		return protocol.CredentialLease{}, invalid
	}

	raw, err := r.challenges.ConsumeChallenge(ctx, "credential-recovery", c.Nonce)
	if err != nil || len(raw) == 0 {
		return protocol.CredentialLease{}, invalid
	}

	expected, _ := json.Marshal(c)
	if !bytes.Equal(raw, expected) {
		return protocol.CredentialLease{}, invalid
	}

	lease, err := r.devices.RecoverCredential(ctx, c.DeviceID, d.IdentityPublicKey)
	if errors.Is(err, devices.ErrDeviceNotFound) {
		return protocol.CredentialLease{}, invalid
	}

	return lease, err
}
