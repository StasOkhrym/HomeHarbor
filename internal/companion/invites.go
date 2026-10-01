package companion

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	"github.com/sokhrym/go-tunnels/internal/invite"
	"github.com/sokhrym/go-tunnels/internal/protocol"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

// InviteIssuer runs only on the trusted Mac companion. Its output is split
// into a link (fragment) and a code, allowing the code to travel separately.
type InviteIssuer struct {
	Session   *Session
	NetworkID string
	BaseURL   string
	KeyID     string
	now       func() time.Time
}

func NewInviteIssuer(
	session *Session,
	networkID, baseURL, keyID string,
	now func() time.Time,
) *InviteIssuer {
	if now == nil {
		now = time.Now
	}

	return &InviteIssuer{
		Session:   session,
		NetworkID: networkID,
		BaseURL:   baseURL,
		KeyID:     keyID,
		now:       now,
	}
}

// Issue creates a signed permit without persisting the short code remotely.
// The caller is responsible for showing Code through a different channel.
func (i *InviteIssuer) Issue(
	profileID string,
	ttl time.Duration,
) (link, code, inviteID string, err error) {
	if i == nil || i.Session == nil || strings.TrimSpace(i.NetworkID) == "" ||
		strings.TrimSpace(i.BaseURL) == "" ||
		strings.TrimSpace(i.KeyID) == "" {
		return "", "", "", errors.New("invite issuer is not configured")
	}

	root, err := i.Session.PrivateKey()
	if err != nil {
		return "", "", "", err
	}

	local, err := invite.New(i.NetworkID, profileID, ttl, i.now().UTC(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}

	permit, err := invite.SignPermit(local.Permit, root, i.KeyID)
	if err != nil {
		return "", "", "", err
	}

	link, err = local.Link(i.BaseURL, permit)
	if err != nil {
		return "", "", "", err
	}

	return link, local.Code, local.Permit.InviteID, nil
}

// RemoteApprover verifies the user-entered code locally and sends only a
// root-signed exact diff to control. The code is never placed in an HTTP body.
type RemoteApprover struct {
	Client      *http.Client
	Endpoint    string
	KeyID       string
	OverlayPool netip.Prefix
	Now         func() time.Time
	Attempts    InviteAttemptStore
}

func (a RemoteApprover) Approve(
	ctx context.Context,
	inviteID, code string,
	root ed25519.PrivateKey,
) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	base := strings.TrimRight(a.Endpoint, "/")
	if err := validateControlEndpoint(base); err != nil {
		return err
	}
	if base == "" || inviteID == "" || code == "" || len(root) != ed25519.PrivateKeySize {
		return errors.New("invalid companion approval request")
	}
	if a.Attempts != nil {
		if err := a.Attempts.Check(inviteID); err != nil {
			return err
		}
	}
	getURL := fmt.Sprintf("%s/api/v1/invites/%s", base, url.PathEscape(inviteID))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return err
	}
	response, err := a.Client.Do(request)
	if err != nil {
		return err
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("load pending invite: status %d", response.StatusCode)
	}
	var pending controlinvites.Record
	if err := json.NewDecoder(response.Body).Decode(&pending); err != nil {
		return err
	}
	if pending.InviteID != inviteID || pending.DeviceID != pending.Proof.DeviceID ||
		!bytes.Equal(pending.DevicePublic, pending.Proof.DevicePublicKey) ||
		!bytes.Equal(pending.WireGuardPublicKey, pending.Proof.WireGuardPublicKey) {
		return invite.ErrInvalidProof
	}
	checkAt := a.Now().UTC()
	if pending.Status == controlinvites.StatusApproved && pending.ApprovedAt != nil {
		checkAt = pending.ApprovedAt.UTC()
	}
	if pending.Status != controlinvites.StatusPending &&
		pending.Status != controlinvites.StatusApproved {
		return controlinvites.ErrInviteConsumed
	}
	network, err := invite.PermitNetworkID(pending.Permit)
	if err != nil {
		return err
	}
	if err := invite.VerifyPermit(
		pending.Permit,
		root.Public().(ed25519.PublicKey),
		network,
		checkAt,
	); err != nil {
		return err
	}
	if err := invite.VerifyProofWithCode(
		pending.Permit,
		pending.Proof,
		pending.ProfileID,
		code,
		checkAt,
	); err != nil {
		// Only a structurally valid proof can consume a local code attempt. The
		// plaintext code and its digest remain inside the companion process.
		if proofErr := invite.VerifyProof(
			pending.Permit,
			pending.Proof,
			pending.ProfileID,
			checkAt,
		); proofErr != nil {
			return proofErr
		}
		if a.Attempts == nil {
			return ErrInviteAttemptsUnavailable
		}
		if attemptErr := a.Attempts.RecordFailure(inviteID); attemptErr != nil {
			return attemptErr
		}
		return err
	}
	signed, err := invite.SignApproval(
		invite.Approval{
			Version:            invite.Version,
			InviteID:           pending.InviteID,
			ProfileID:          pending.ProfileID,
			DeviceID:           pending.DeviceID,
			DevicePublicKey:    pending.DevicePublic,
			WireGuardPublicKey: pending.Proof.WireGuardPublicKey,
		},
		root,
	)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]invite.SignedApproval{"approval": signed})
	if err != nil {
		return err
	}
	approvalURL := fmt.Sprintf("%s/api/v1/invites/%s/approval", base, url.PathEscape(inviteID))
	request, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		approvalURL,
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = a.Client.Do(request)
	if err != nil {
		return err
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("approve invite: status %d", response.StatusCode)
	}
	var result controlinvites.ApprovalResult
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return errors.New("invalid public approval response")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("invalid public approval response")
	}
	if result.InviteID != pending.InviteID || result.DeviceID != pending.DeviceID ||
		result.ProfileID != pending.ProfileID ||
		result.Status != controlinvites.StatusApproved {
		return errors.New("approval response differs from signed public diff")
	}
	return nil
}

// PublishSnapshot retries the second onboarding step after activation. It is
// intentionally separate from Approve: activation is durable, while snapshot
// publication depends on the current control connection and can be retried
// without consuming another invite or credential.
func (a RemoteApprover) PublishSnapshot(
	ctx context.Context,
	inviteID string,
	root ed25519.PrivateKey,
) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.KeyID == "" {
		a.KeyID = "root-1"
	}
	if strings.TrimSpace(a.Endpoint) == "" || inviteID == "" ||
		len(root) != ed25519.PrivateKeySize ||
		!a.OverlayPool.IsValid() {
		return errors.New("invalid companion snapshot publication request")
	}
	base := strings.TrimRight(a.Endpoint, "/")
	if err := validateControlEndpoint(base); err != nil {
		return err
	}
	getURL := fmt.Sprintf("%s/api/v1/invites/%s", base, url.PathEscape(inviteID))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return err
	}
	response, err := a.Client.Do(request)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return fmt.Errorf("load approved invite: status %d", response.StatusCode)
	}
	var record controlinvites.Record
	if err := json.NewDecoder(response.Body).Decode(&record); err != nil {
		_ = response.Body.Close()
		return err
	}
	_ = response.Body.Close()
	if record.Status != controlinvites.StatusApproved {
		return errors.New("invite is not approved")
	}
	permitNetworkID, err := invite.PermitNetworkID(record.Permit)
	if err != nil {
		return err
	}

	previous, snapshotNetwork, err := a.loadSignedSnapshot(ctx, root)
	if err != nil {
		return err
	}
	if snapshotNetwork != permitNetworkID {
		return errors.New("invite and signed snapshot belong to different networks")
	}
	var wireGuard wgtypes.Key
	if len(record.WireGuardPublicKey) != len(wireGuard) {
		return invite.ErrInvalidProof
	}
	copy(wireGuard[:], record.WireGuardPublicKey)
	session := NewSession(a.Now)
	if err := session.Unlock(root); err != nil {
		return err
	}
	next, err := NewSnapshotSigner(
		session,
		snapshotNetwork,
		a.KeyID,
	).SignDeviceAdditionFromPool(previous, DeviceAddition{ProfileID: record.ProfileID, Device: snapshot.Device{
		ID:                 record.DeviceID,
		Role:               "client",
		IdentityPublicKey:  base64.RawURLEncoding.EncodeToString(record.DevicePublic),
		WireGuardPublicKey: wireGuard.String(),
	}}, a.OverlayPool)
	session.Close()
	if err != nil {
		return fmt.Errorf("sign snapshot for invite %s: %w", inviteID, err)
	}
	return a.publishSignedSnapshot(ctx, base, next)
}

// PublishInitialSnapshot sends revision one after the local companion has
// signed an operator-authored manifest. The control service performs the
// authoritative root-signature and empty-store checks.
func (a RemoteApprover) PublishInitialSnapshot(
	ctx context.Context,
	envelope snapshot.Envelope,
) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}

	if strings.TrimSpace(a.Endpoint) == "" {
		return errors.New("control endpoint is required")
	}

	base := strings.TrimRight(a.Endpoint, "/")
	if err := validateControlEndpoint(base); err != nil {
		return err
	}

	value, err := snapshot.Decode(envelope)
	if err != nil {
		return fmt.Errorf("validate initial snapshot: %w", err)
	}
	if value.Revision != 1 || len(value.PreviousHash) != 0 {
		return errors.New("initial snapshot must be revision one without a previous hash")
	}

	return a.publishSignedSnapshot(ctx, base, envelope)
}

// PublishDeviceRemoval publishes the signed snapshot that revokes one client
// from the node data plane. The control plane only transports this envelope;
// it cannot manufacture the removal or broaden it to a gateway/route change.
func (a RemoteApprover) PublishDeviceRemoval(
	ctx context.Context,
	deviceID string,
	root ed25519.PrivateKey,
) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}

	if a.Now == nil {
		a.Now = time.Now
	}

	if a.KeyID == "" {
		a.KeyID = "root-1"
	}

	if strings.TrimSpace(a.Endpoint) == "" || strings.TrimSpace(deviceID) == "" ||
		len(root) != ed25519.PrivateKeySize {
		return errors.New("invalid companion device-removal request")
	}

	base := strings.TrimRight(a.Endpoint, "/")
	if err := validateControlEndpoint(base); err != nil {
		return err
	}

	previous, networkID, err := a.loadSignedSnapshot(ctx, root)
	if err != nil {
		return err
	}

	session := NewSession(a.Now)
	if err := session.Unlock(root); err != nil {
		return err
	}

	next, err := NewSnapshotSigner(
		session,
		networkID,
		a.KeyID,
	).SignDeviceRemoval(previous, DeviceRemoval{DeviceID: deviceID})
	session.Close()
	if err != nil {
		return fmt.Errorf("sign device removal for %s: %w", deviceID, err)
	}

	return a.publishSignedSnapshot(ctx, base, next)
}

func (a RemoteApprover) loadSignedSnapshot(
	ctx context.Context,
	root ed25519.PrivateKey,
) (snapshot.Envelope, string, error) {
	base := strings.TrimRight(a.Endpoint, "/")
	const snapshotPath = "/api/v1/coordination/snapshot/companion"
	challengeURL := base + "/api/v1/coordination/snapshot/companion-challenge"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, challengeURL, nil)
	if err != nil {
		return snapshot.Envelope{}, "", err
	}
	response, err := a.Client.Do(request)
	if err != nil {
		return snapshot.Envelope{}, "", err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return snapshot.Envelope{}, "", fmt.Errorf(
			"load companion challenge: status %d",
			response.StatusCode,
		)
	}
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(response.Body).Decode(&challenge); err != nil {
		_ = response.Body.Close()
		return snapshot.Envelope{}, "", err
	}
	_ = response.Body.Close()
	if challenge.Nonce == "" {
		return snapshot.Envelope{}, "", errors.New("companion challenge is empty")
	}
	signature, err := protocol.SignCompanionRequest(
		http.MethodGet,
		snapshotPath,
		challenge.Nonce,
		a.KeyID,
		root,
	)
	if err != nil {
		return snapshot.Envelope{}, "", err
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, base+snapshotPath, nil)
	if err != nil {
		return snapshot.Envelope{}, "", err
	}
	request.Header.Set("X-Go-Tunnels-Companion-Nonce", challenge.Nonce)
	request.Header.Set("X-Go-Tunnels-Companion-Key-ID", a.KeyID)
	request.Header.Set(
		"X-Go-Tunnels-Companion-Signature",
		base64.RawURLEncoding.EncodeToString(signature),
	)
	response, err = a.Client.Do(request)
	if err != nil {
		return snapshot.Envelope{}, "", err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return snapshot.Envelope{}, "", fmt.Errorf(
			"load signed snapshot: status %d",
			response.StatusCode,
		)
	}
	var previous snapshot.Envelope
	if err := json.NewDecoder(response.Body).Decode(&previous); err != nil {
		_ = response.Body.Close()
		return snapshot.Envelope{}, "", err
	}
	_ = response.Body.Close()
	networkID, err := snapshotNetworkID(previous)
	if err != nil {
		return snapshot.Envelope{}, "", err
	}
	return previous, networkID, nil
}

func snapshotNetworkID(envelope snapshot.Envelope) (string, error) {
	value, err := snapshot.Decode(envelope)
	if err != nil {
		return "", fmt.Errorf("decode current snapshot: %w", err)
	}

	return value.NetworkID, nil
}

func (a RemoteApprover) publishSignedSnapshot(
	ctx context.Context,
	base string,
	next snapshot.Envelope,
) error {
	body, err := json.Marshal(next)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		base+"/api/v1/coordination/snapshots",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.Client.Do(request)
	if err != nil {
		return err
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(response.Body)
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("publish signed snapshot: status %d", response.StatusCode)
	}
	return nil
}

func validateControlEndpoint(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		parsed.Path != "" {
		return errors.New(
			"control endpoint must be an origin without credentials, path, query, or fragment",
		)
	}
	if parsed.Scheme == "https" {
		return nil
	}

	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}

	return errors.New("control endpoint must use HTTPS; HTTP is allowed only for localhost testing")
}
