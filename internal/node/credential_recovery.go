package node

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

// RecoverCredential obtains a fresh lease with the existing persisted identity.
// The caller must durably save this state through its lifetime localstate owner
// before publishing the lease to transports. It never enrolls a new identity.
func RecoverCredential(
	ctx context.Context,
	client *http.Client,
	controlURL, network string,
	state *State,
) error {
	if state == nil || state.DeviceID == "" || network == "" {
		return errors.New("node identity and network are required")
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(state.IdentityPrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid node identity")
	}
	if client == nil {
		client = http.DefaultClient
	}
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	endpoint := strings.TrimRight(controlURL, "/") + "/api/v1/devices/credentials"
	var challenge protocol.CredentialChallenge
	status, err := activationRequest(ctx, &bounded, endpoint+"/challenge", struct {
		DeviceID string `json:"device_id"`
	}{state.DeviceID}, &challenge)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return errors.New("credential challenge unavailable")
	}
	now := time.Now()
	if challenge.DeviceID != state.DeviceID || challenge.NetworkID != network ||
		challenge.ExpiresAt <= now.Unix() ||
		challenge.ExpiresAt > now.Add(protocol.CredentialChallengeTTL).Unix() {
		return protocol.ErrInvalidCredentialProof
	}
	proof, err := protocol.SignCredentialProof(challenge, ed25519.PrivateKey(key))
	if err != nil {
		return err
	}
	var lease protocol.CredentialLease
	status, err = activationRequest(ctx, &bounded, endpoint+"/recovery", proof, &lease)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return errors.New("credential recovery failed")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(lease.Credential)
	if err != nil || len(raw) != 32 ||
		base64.RawURLEncoding.EncodeToString(raw) != lease.Credential ||
		lease.DeviceID != state.DeviceID ||
		!lease.ExpiresAt.After(time.Now()) ||
		lease.ExpiresAt.After(time.Now().Add(15*time.Minute)) {
		return errors.New("invalid recovered credential lease")
	}
	state.DeviceCredential = lease.Credential
	state.CredentialExpiresAt = lease.ExpiresAt
	return nil
}
