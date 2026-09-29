package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	defer response.Body.Close()
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
