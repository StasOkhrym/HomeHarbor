package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

func Enroll(ctx context.Context, httpClient *http.Client, controlURL, token, name string, state *State) error {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	body, err := json.Marshal(devices.EnrollRequest{Token: token, Name: name, IdentityPublicKey: state.IdentityPublicKey, WireGuardPublicKey: state.WireGuard.PublicKey})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(controlURL, "/")+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("enroll device: %w", err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(response.Body)
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("enroll device: control plane returned %s", response.Status)
	}
	var device devices.Device
	if err = json.NewDecoder(response.Body).Decode(&device); err != nil {
		return err
	}
	if device.ID == "" || device.Credential == "" {
		return errors.New("control plane returned incomplete enrollment")
	}
	state.DeviceID = device.ID
	state.DeviceCredential = device.Credential
	return nil
}

// RefreshCredential rotates the bearer credential before its short lifetime
// expires. Only the current credential is sent; the replacement is persisted
// by the caller through the same atomic state-file path as enrollment.
func RefreshCredential(ctx context.Context, httpClient *http.Client, controlURL string, state *State) error {
	if state == nil || state.DeviceID == "" || state.DeviceCredential == "" {
		return errors.New("node identity and credential are required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(controlURL, "/")+"/api/v1/devices/credentials/rotate", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+state.DeviceCredential)
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("rotate device credential: %w", err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("rotate device credential: control plane returned %s", response.Status)
	}
	var result struct {
		Credential string `json:"credential"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return err
	}
	if result.Credential == "" {
		return errors.New("control plane returned an empty rotated credential")
	}
	state.DeviceCredential = result.Credential
	return nil
}

// RelaySession is the short-lived, device-bound authorization returned by
// control before a node opens a relay WebSocket.
type RelaySession struct {
	SessionID           string `json:"session_id"`
	DeviceID            string `json:"device_id"`
	DestinationDeviceID string `json:"destination_device_id"`
	RelayURL            string `json:"relay_url"`
	Ticket              string `json:"ticket"`
	ExpiresInSeconds    int64  `json:"expires_in_seconds"`
}

// IssueRelaySession asks control for a ticket for the current device. The
// destination is checked by control against active device state; the node does
// not construct or sign relay credentials locally.
func IssueRelaySession(ctx context.Context, httpClient *http.Client, controlURL, credential, sessionID, destinationDeviceID string) (RelaySession, error) {
	if strings.TrimSpace(credential) == "" || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(destinationDeviceID) == "" {
		return RelaySession{}, errors.New("credential, session, and destination device are required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	body, err := json.Marshal(struct {
		SessionID           string `json:"session_id"`
		DestinationDeviceID string `json:"destination_device_id"`
	}{sessionID, destinationDeviceID})
	if err != nil {
		return RelaySession{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(controlURL, "/")+"/api/v1/relay-sessions", bytes.NewReader(body))
	if err != nil {
		return RelaySession{}, err
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		return RelaySession{}, fmt.Errorf("issue relay session: %w", err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(response.Body)
	if response.StatusCode != http.StatusCreated {
		return RelaySession{}, fmt.Errorf("issue relay session: control plane returned %s", response.Status)
	}
	var session RelaySession
	if err := json.NewDecoder(response.Body).Decode(&session); err != nil {
		return RelaySession{}, err
	}
	if session.Ticket == "" || session.RelayURL == "" || session.SessionID != sessionID {
		return RelaySession{}, errors.New("control plane returned incomplete relay session")
	}
	return session, nil
}
