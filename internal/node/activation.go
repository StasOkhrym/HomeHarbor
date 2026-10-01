package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sokhrym/go-tunnels/internal/app/control/workflows"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/invite"
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
}

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
func PrepareInviteProof(p InviteEnrollment, state State, now time.Time) (invite.SignedPermit, invite.Proof, error) {
	if err := state.Validate(); err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}
	if p.DeviceID == "" || state.DeviceID != "" && state.DeviceID != p.DeviceID || len(p.Code) != 8 {
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
	if err != nil || len(fragment) != 2 || len(fragment["permit"]) != 1 || len(fragment["invite_key"]) != 1 {
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
	digest := sha256.Sum256(append([]byte("go-tunnels/invite-code/v1\x00"), []byte(p.Code)...))
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
	message := append([]byte("go-tunnels/invite-proof/v1\x00"), payload...)
	proof.Signature = ed25519.Sign(invitePrivate, message)
	proof.DeviceSignature = ed25519.Sign(devicePrivate, message)
	if err = invite.VerifyProof(signed, proof, permit.ProfileID, now); err != nil {
		return invite.SignedPermit{}, invite.Proof{}, err
	}
	return signed, proof, nil
}

func activationOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return "", errors.New("control URL must be an origin")
	}
	if u.Scheme == "https" ||
		u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1") {
		return strings.TrimRight(raw, "/"), nil
	}
	return "", errors.New("control URL must use HTTPS or local HTTP")
}

func activationRequest(ctx context.Context, client *http.Client, target string, body any, result any) (int, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, target, reader)
	if err != nil {
		return 0, err
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= 200 && response.StatusCode < 300 && result != nil {
		decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(result); err != nil {
			return response.StatusCode, err
		}
		if err = decoder.Decode(new(any)); err != io.EOF {
			return response.StatusCode, errors.New("invalid activation response")
		}
	}
	return response.StatusCode, nil
}

// EnrollByInvite submits the proof, polls until approval appears in signed
// topology, then claims and atomically saves a credential using existing State
// keys. Lost claim responses are recovered with a fresh challenge/credential.
// Context cancellation bounds polling; a caller may retry with the same state.
func EnrollByInvite(ctx context.Context, httpClient *http.Client, p InviteEnrollment, state *State) error {
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
	if err := state.Save(p.StatePath); err != nil {
		return err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	status, err := activationRequest(ctx, &client, base+"/api/v1/invites/proof", struct {
		Permit invite.SignedPermit `json:"permit"`
		Proof  invite.Proof        `json:"proof"`
	}{permit, proof}, nil)
	if err != nil {
		return err
	}
	if status != http.StatusAccepted {
		return fmt.Errorf("submit invite proof: status %d", status)
	}
	interval := p.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	endpoint := base + "/api/v1/invites/" + url.PathEscape(proof.InviteID)
	private, err := strictInviteBytes(state.IdentityPrivateKey, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	for {
		var challenge workflows.ClaimChallenge
		status, err = activationRequest(ctx, &client, endpoint+"/challenge", nil, &challenge)
		if err == nil && status == http.StatusOK {
			if challenge.InviteID != proof.InviteID || challenge.DeviceID != p.DeviceID ||
				challenge.NetworkID != p.NetworkID ||
				challenge.ExpiresAt <= time.Now().Unix() ||
				challenge.ExpiresAt > time.Now().Add(workflows.ClaimTTL).Unix() {
				return workflows.ErrInvalidClaim
			}
			signed, signErr := workflows.SignClaim(challenge, ed25519.PrivateKey(private))
			if signErr != nil {
				return signErr
			}
			var result workflows.ClaimResult
			status, err = activationRequest(ctx, &client, endpoint+"/claim", signed, &result)
			if err == nil && status == http.StatusOK {
				d := result.Device
				if d.ID != p.DeviceID || d.Status != devices.StatusActive || d.Role != devices.RoleClient ||
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
				if err := updated.Save(p.StatePath); err != nil {
					return err
				}
				*state = updated
				return nil
			}
		}
		if err == nil && status != http.StatusConflict && status != http.StatusServiceUnavailable &&
			status != http.StatusTooManyRequests {
			return fmt.Errorf("activate invite: status %d", status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
