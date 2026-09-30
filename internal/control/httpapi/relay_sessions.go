package httpapi

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/protocol"
	"github.com/sokhrym/go-tunnels/internal/relay"
)

func (s *Server) issueRelaySession(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID           string   `json:"session_id"`
		DestinationDeviceID string   `json:"destination_device_id"`
		Capabilities        []string `json:"capabilities"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	credential := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	source, err := s.devices.Authenticate(r.Context(), credential)
	if err != nil || source.Status != devices.StatusActive {
		writeError(w, http.StatusUnauthorized, "device authentication required")
		return
	}
	destination, err := s.devices.Device(r.Context(), strings.TrimSpace(input.DestinationDeviceID))
	if err != nil || destination.Status != devices.StatusActive || destination.ID == source.ID {
		writeError(w, http.StatusForbidden, "destination device is unavailable")
		return
	}
	// MVP relay sessions connect one external client to one LAN gateway. Do
	// not accidentally turn the relay into an unrestricted device mesh before
	// an explicit peer-policy model exists.
	if source.Role == destination.Role || (source.Role != devices.RoleClient && source.Role != devices.RoleGateway) {
		writeError(w, http.StatusForbidden, "device peer role is not allowed")
		return
	}
	if s.relayPeerAuthorizer != nil && !s.relayPeerAuthorizer(r.Context(), source, destination) {
		writeError(w, http.StatusForbidden, "device peer is not authorized")
		return
	}
	if strings.TrimSpace(input.SessionID) == "" {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}
	if !slices.Contains(input.Capabilities, protocol.CapabilityUDPPairV2) {
		writeErrorCode(w, http.StatusUpgradeRequired, protocol.ErrorUpgradeRequired, "udp_pair_v2 capability required")
		return
	}
	if !strings.HasPrefix(s.relayURL, "wss://") || !strings.HasSuffix(s.relayURL, "/relay/udp/v2") {
		writeError(w, http.StatusServiceUnavailable, "verified TLS UDP v2 relay unavailable")
		return
	}
	if s.relayTTL <= 0 {
		writeError(w, http.StatusServiceUnavailable, "relay sessions are unavailable")
		return
	}
	ticket, err := s.relayIssuer.IssueForPeer(input.SessionID, source.ID, destination.ID, s.relayTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue relay session")
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		SessionID           string `json:"session_id"`
		DeviceID            string `json:"device_id"`
		DestinationDeviceID string `json:"destination_device_id"`
		RelayURL            string `json:"relay_url"`
		RelayTransport      string `json:"relay_transport"`
		Ticket              string `json:"ticket"`
		ExpiresInSeconds    int64  `json:"expires_in_seconds"`
	}{input.SessionID, source.ID, destination.ID, s.relayURL, relay.UDPPairV2Protocol, ticket, int64(s.relayTTL / time.Second)})
}
