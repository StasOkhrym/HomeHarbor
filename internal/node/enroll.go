package node

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/controlclient"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func Enroll(
	ctx context.Context,
	httpClient *http.Client,
	controlURL, token, name string,
	state *State,
) error {
	return enroll(ctx, httpClient, controlURL, token, name, state, "")
}

// EnrollGateway bootstraps the trusted gateway role before any tunnel runs.
// A client-role token or a response for different public keys cannot admit it.
func EnrollGateway(
	ctx context.Context,
	httpClient *http.Client,
	controlURL, token, name string,
	state *State,
) error {
	return enroll(ctx, httpClient, controlURL, token, name, state, "gateway")
}

func enroll(
	ctx context.Context,
	httpClient *http.Client,
	controlURL, token, name string,
	state *State,
	role string,
) error {
	if state == nil {
		return errors.New("node identity is required")
	}

	client, err := controlclient.ForEndpoint(strings.TrimRight(controlURL, "/"), httpClient)
	if err != nil {
		return err
	}

	device, err := client.Enroll(ctx, protocol.EnrollmentRequest{
		Token:              token,
		Name:               name,
		IdentityPublicKey:  state.IdentityPublicKey,
		WireGuardPublicKey: state.WireGuard.PublicKey,
	})
	if err != nil {
		return fmt.Errorf("enroll device: %w", err)
	}
	if device.ID == "" || device.Credential == "" || device.CredentialExpiresAt.IsZero() {
		return errors.New("control plane returned incomplete enrollment")
	}
	if role != "" && (device.Role != role || device.Status != "active" ||
		device.IdentityPublicKey != state.IdentityPublicKey ||
		device.WireGuardPublicKey != state.WireGuard.PublicKey ||
		!device.CredentialExpiresAt.After(time.Now())) {
		return errors.New("control plane enrollment does not match gateway role and identity")
	}

	state.DeviceID = device.ID
	state.DeviceCredential = device.Credential
	state.CredentialExpiresAt = device.CredentialExpiresAt
	state.DeviceRole = device.Role

	return nil
}

// RefreshCredential rotates the bearer credential before its short lifetime
// expires. Only the current credential is sent; the replacement is persisted
// by the caller through the same atomic state-file path as enrollment.
func RefreshCredential(
	ctx context.Context,
	httpClient *http.Client,
	controlURL string,
	state *State,
) error {
	if state == nil || state.DeviceID == "" || state.DeviceCredential == "" {
		return errors.New("node identity and credential are required")
	}

	client, err := controlclient.ForEndpoint(strings.TrimRight(controlURL, "/"), httpClient)
	if err != nil {
		return err
	}

	result, err := client.RotateCredential(ctx, state.DeviceCredential)
	if err != nil {
		return fmt.Errorf("rotate device credential: %w", err)
	}
	if result.Credential == "" || result.DeviceID != state.DeviceID || result.ExpiresAt.IsZero() {
		return errors.New("control plane returned an empty rotated credential")
	}

	state.DeviceCredential = result.Credential
	state.CredentialExpiresAt = result.ExpiresAt

	return nil
}

// RelaySession is the short-lived, device-bound authorization returned by
// control before a node opens a relay WebSocket.
type RelaySession struct {
	SessionID           string `json:"session_id"`
	DeviceID            string `json:"device_id"`
	DestinationDeviceID string `json:"destination_device_id"`
	RelayURL            string `json:"relay_url"`
	RelayTransport      string `json:"relay_transport"`
	Ticket              string `json:"ticket"`
	ExpiresInSeconds    int64  `json:"expires_in_seconds"`
}

// IssueRelaySession asks control for a ticket for the current device. The
// destination is checked by control against active device state; the node does
// not construct or sign relay credentials locally.
func IssueRelaySession(
	ctx context.Context,
	httpClient *http.Client,
	controlURL, credential, sessionID, destinationDeviceID string,
) (RelaySession, error) {
	if strings.TrimSpace(credential) == "" || strings.TrimSpace(sessionID) == "" ||
		strings.TrimSpace(destinationDeviceID) == "" {
		return RelaySession{}, errors.New(
			"credential, session, and destination device are required",
		)
	}

	client, err := controlclient.ForEndpoint(strings.TrimRight(controlURL, "/"), httpClient)
	if err != nil {
		return RelaySession{}, err
	}

	wire, err := client.IssueRelaySession(ctx, credential, protocol.RelaySessionRequest{
		SessionID: sessionID, DestinationDeviceID: destinationDeviceID,
		Capabilities: []string{protocol.CapabilityUDPPair},
	})
	if err != nil {
		return RelaySession{}, fmt.Errorf("issue relay session: %w", err)
	}

	session := RelaySession{
		SessionID: wire.SessionID, DeviceID: wire.DeviceID,
		DestinationDeviceID: wire.DestinationDeviceID, RelayURL: wire.RelayURL,
		RelayTransport: wire.RelayTransport,
		Ticket:         wire.Ticket, ExpiresInSeconds: wire.ExpiresInSeconds,
	}
	if session.Ticket == "" || protocol.ValidateRelayControlURL(session.RelayURL) != nil ||
		session.RelayTransport != protocol.CapabilityUDPPair ||
		session.SessionID != sessionID ||
		session.DestinationDeviceID != destinationDeviceID {
		return RelaySession{}, errors.New("control plane returned incomplete relay session")
	}

	return session, nil
}
