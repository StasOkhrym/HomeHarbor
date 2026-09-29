package companion

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	"github.com/sokhrym/go-tunnels/internal/invite"
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
	Client   *http.Client
	Endpoint string
	Now      func() time.Time
}

func (a RemoteApprover) Approve(ctx context.Context, inviteID, code string, root ed25519.PrivateKey) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	base := strings.TrimRight(a.Endpoint, "/")
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
	signed, err := invite.SignApproval(invite.Approval{Version: invite.Version, InviteID: pending.InviteID, ProfileID: pending.ProfileID, DeviceID: pending.DeviceID, DevicePublicKey: pending.DevicePublic}, root)
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
