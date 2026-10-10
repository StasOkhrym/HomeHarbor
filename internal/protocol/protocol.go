package protocol

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const CurrentVersion uint16 = 1
const (
	// CapabilityUDPPair identifies authenticated per-peer UDP ingress, not
	// the old bearer-bearing datagram format. It must be negotiated explicitly.
	CapabilityUDPPair   = "udp_pair"
	CapabilityDirectUDP = "direct-udp-v1"
	CapabilitySplitDNS  = "split-dns-v1"
)
const ErrorUpgradeRequired = "upgrade_required"

type Hello struct {
	Versions     []uint16 `json:"versions"`
	Capabilities []string `json:"capabilities"`
	DeviceID     string   `json:"device_id,omitempty"`
}
type Negotiated struct {
	Version      uint16   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

func (n Negotiated) Has(
	capability string,
) bool {
	return slices.Contains(n.Capabilities, capability)
}

type ProtocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ProtocolError) Error() string { return e.Code + ": " + e.Message }
func Negotiate(hello Hello) (Negotiated, *ProtocolError) {
	if !slices.Contains(hello.Versions, CurrentVersion) {
		return Negotiated{}, &ProtocolError{
			Code:    ErrorUpgradeRequired,
			Message: "client does not support protocol version 1",
		}
	}
	if !slices.Contains(hello.Capabilities, CapabilityUDPPair) {
		return Negotiated{}, &ProtocolError{
			Code:    ErrorUpgradeRequired,
			Message: "a supported relay capability is required",
		}
	}
	supported := []string{}
	for _, c := range []string{CapabilityUDPPair, CapabilityDirectUDP, CapabilitySplitDNS} {
		if slices.Contains(hello.Capabilities, c) {
			supported = append(supported, c)
		}
	}
	return Negotiated{Version: CurrentVersion, Capabilities: supported}, nil
}

type CandidateType string

const (
	CandidateHost            CandidateType = "host"
	CandidateServerReflexive CandidateType = "server_reflexive"
	CandidateRelay           CandidateType = "relay"
)

type Candidate struct {
	Type     CandidateType `json:"type"`
	Address  string        `json:"address"`
	Priority uint32        `json:"priority"`
}

// CandidateUpdate is always addressed to one peer. Broadcasting endpoint
// candidates would disclose home-network topology to unrelated devices.
type CandidateUpdate struct {
	// SourceDeviceID is populated by the authenticated coordination handler
	// before forwarding. It prevents a receiver from applying an endpoint
	// update intended for a different peer.
	SourceDeviceID      string      `json:"source_device_id,omitempty"`
	DestinationDeviceID string      `json:"destination_device_id"`
	Candidates          []Candidate `json:"candidates"`
}

const maxCandidates = 8

// Validate bounds candidate exchange before an endpoint can reach a peer. The
// control connection authenticates the sender, but it does not make arbitrary
// addresses safe: rejecting empty, duplicate, or unusable endpoints prevents
// a malformed update from turning into an unbounded direct-dial loop.
func (u CandidateUpdate) Validate() error {
	if strings.TrimSpace(u.DestinationDeviceID) == "" {
		return fmt.Errorf("candidate destination device is required")
	}
	if len(u.Candidates) == 0 || len(u.Candidates) > maxCandidates {
		return fmt.Errorf("candidate count must be between 1 and %d", maxCandidates)
	}

	seen := make(map[string]struct{}, len(u.Candidates))
	for _, candidate := range u.Candidates {
		switch candidate.Type {
		case CandidateHost, CandidateServerReflexive, CandidateRelay:
		default:
			return fmt.Errorf("unsupported candidate type %q", candidate.Type)
		}

		if candidate.Priority == 0 {
			return fmt.Errorf("candidate priority must be positive")
		}

		address, err := netip.ParseAddrPort(candidate.Address)
		if err != nil || !address.IsValid() || address.Port() == 0 ||
			address.Addr().IsUnspecified() {
			return fmt.Errorf("invalid candidate address %q", candidate.Address)
		}

		key := string(candidate.Type) + "\x00" + address.String()
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate candidate %q", candidate.Address)
		}

		seen[key] = struct{}{}
	}

	return nil
}

type Message struct {
	Type     string          `json:"type"`
	Revision uint64          `json:"revision,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

type Path string

const (
	PathRelay  Path = "relay"
	PathDirect Path = "direct"
)
