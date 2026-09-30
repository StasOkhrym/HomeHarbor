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

func NewInviteIssuer(session *Session, networkID, baseURL, keyID string, now func() time.Time) *InviteIssuer {
	if now == nil {
		now = time.Now
	}
	return &InviteIssuer{Session: session, NetworkID: networkID, BaseURL: baseURL, KeyID: keyID, now: now}
}

// Issue creates a signed permit without persisting the short code remotely.
// The caller is responsible for showing Code through a different channel.
func (i *InviteIssuer) Issue(profileID string, ttl time.Duration) (link, code, inviteID string, err error) {
	if i == nil || i.Session == nil || strings.TrimSpace(i.NetworkID) == "" || strings.TrimSpace(i.BaseURL) == "" || strings.TrimSpace(i.KeyID) == "" {
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
}

func (a RemoteApprover) Approve(ctx context.Context, inviteID, code string, root ed25519.PrivateKey) error {
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
	if err := invite.VerifyProofWithCode(pending.Permit, pending.Proof, pending.ProfileID, code, a.Now().UTC()); err != nil {
		return err
	}
	signed, err := invite.SignApproval(invite.Approval{Version: invite.Version, InviteID: pending.InviteID, ProfileID: pending.ProfileID, DeviceID: pending.DeviceID, DevicePublicKey: pending.DevicePublic, WireGuardPublicKey: pending.Proof.WireGuardPublicKey}, root)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]invite.SignedApproval{"approval": signed})
	if err != nil {
		return err
	}
	approvalURL := fmt.Sprintf("%s/api/v1/invites/%s/approval", base, url.PathEscape(inviteID))
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, approvalURL, bytes.NewReader(body))
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
	return nil
}

// PublishSnapshot retries the second onboarding step after activation. It is
// intentionally separate from Approve: activation is durable, while snapshot
// publication depends on the current control connection and can be retried
// without consuming another invite or credential.
func (a RemoteApprover) PublishSnapshot(ctx context.Context, inviteID string, root ed25519.PrivateKey) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.KeyID == "" {
		a.KeyID = "root-1"
	}
	if strings.TrimSpace(a.Endpoint) == "" || inviteID == "" || len(root) != ed25519.PrivateKeySize || !a.OverlayPool.IsValid() {
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
	networkID, err := invite.PermitNetworkID(record.Permit)
	if err != nil {
		return err
	}

	const snapshotPath = "/api/v1/coordination/snapshot/companion"
	challengeURL := base + "/api/v1/coordination/snapshot/companion-challenge"
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, challengeURL, nil)
	if err != nil {
		return err
	}
	response, err = a.Client.Do(request)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return fmt.Errorf("load companion challenge: status %d", response.StatusCode)
	}
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(response.Body).Decode(&challenge); err != nil {
		_ = response.Body.Close()
		return err
	}
	_ = response.Body.Close()
	if challenge.Nonce == "" {
		return errors.New("companion challenge is empty")
	}
	signature, err := protocol.SignCompanionRequest(http.MethodGet, snapshotPath, challenge.Nonce, a.KeyID, root)
	if err != nil {
		return err
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, base+snapshotPath, nil)
	if err != nil {
		return err
	}
	request.Header.Set("X-Go-Tunnels-Companion-Nonce", challenge.Nonce)
	request.Header.Set("X-Go-Tunnels-Companion-Key-ID", a.KeyID)
	request.Header.Set("X-Go-Tunnels-Companion-Signature", base64.RawURLEncoding.EncodeToString(signature))
	response, err = a.Client.Do(request)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return fmt.Errorf("load signed snapshot: status %d", response.StatusCode)
	}
	var previous snapshot.Envelope
	if err := json.NewDecoder(response.Body).Decode(&previous); err != nil {
		_ = response.Body.Close()
		return err
	}
	_ = response.Body.Close()
	session := NewSession(a.Now)
	if err := session.Unlock(root); err != nil {
		return err
	}
	next, err := NewSnapshotSigner(session, networkID, a.KeyID).SignDeviceAdditionFromPool(previous, DeviceAddition{ProfileID: record.ProfileID, Device: snapshot.Device{
		ID: record.DeviceID, Role: "client", IdentityPublicKey: base64.RawURLEncoding.EncodeToString(record.DevicePublic), WireGuardPublicKey: base64.RawURLEncoding.EncodeToString(record.WireGuardPublicKey),
	}}, a.OverlayPool)
	session.Close()
	if err != nil {
		return fmt.Errorf("sign snapshot for invite %s: %w", inviteID, err)
	}
	body, err := json.Marshal(next)
	if err != nil {
		return err
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/coordination/snapshots", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = a.Client.Do(request)
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
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return errors.New("control endpoint must be an origin without credentials, path, query, or fragment")
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
