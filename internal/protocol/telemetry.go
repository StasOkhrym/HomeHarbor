package protocol

import (
	"errors"
	"math"
	"net/netip"

	"github.com/google/uuid"
)

const (
	CapabilityTelemetry      = "telemetry-v1"
	MaxTelemetryObservations = 128
)

type RuntimeState string

const (
	RuntimeStarting RuntimeState = "starting"
	RuntimeRunning  RuntimeState = "running"
	RuntimeStopped  RuntimeState = "stopped"
	RuntimeFailed   RuntimeState = "failed"
)

// TelemetryReport is one complete snapshot of a reporter's current observations.
// Generation is issued by control for this connection, never by the reporter.
// RuntimeID remains stable for the VPN lifetime across credential reconnects.
type TelemetryReport struct {
	Generation      uint64            `json:"generation"`
	Sequence        uint64            `json:"sequence"`
	RuntimeID       string            `json:"runtime_id"`
	State           RuntimeState      `json:"state"`
	AppliedRevision uint64            `json:"applied_revision"`
	Observations    []PeerObservation `json:"observations"`
}

// PeerObservation describes reported WireGuard facts, not proof of reachability.
// Endpoint can be relay loopback; it is not the subject device's public IP.
type PeerObservation struct {
	DeviceID          string `json:"device_id"`
	LastHandshakeUnix int64  `json:"last_handshake_unix,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	Path              Path   `json:"path,omitempty"`
	RXBytes           uint64 `json:"rx_bytes"`
	TXBytes           uint64 `json:"tx_bytes"`
}

type Welcome struct {
	Type                string     `json:"type"`
	Protocol            Negotiated `json:"protocol"`
	TelemetryGeneration uint64     `json:"telemetry_generation,omitempty"`
}

func (r TelemetryReport) Validate() error {
	invalid := errors.New("invalid telemetry report")
	if r.Generation == 0 || r.Generation > math.MaxInt64 || r.Sequence == 0 ||
		r.Sequence > math.MaxInt64 ||
		r.AppliedRevision > math.MaxInt64 {
		return invalid
	}
	id, err := uuid.Parse(r.RuntimeID)
	if err != nil || id.String() != r.RuntimeID || id == uuid.Nil {
		return invalid
	}
	switch r.State {
	case RuntimeStarting, RuntimeRunning, RuntimeStopped, RuntimeFailed:
	default:
		return invalid
	}
	if len(r.Observations) == 0 || len(r.Observations) > MaxTelemetryObservations {
		return invalid
	}
	seen := map[string]bool{}
	for _, sample := range r.Observations {
		if !telemetryDeviceID(sample.DeviceID) || seen[sample.DeviceID] ||
			sample.RXBytes > math.MaxInt64 ||
			sample.TXBytes > math.MaxInt64 ||
			sample.LastHandshakeUnix < 0 {
			return invalid
		}
		seen[sample.DeviceID] = true
		if sample.Endpoint != "" {
			endpoint, err := netip.ParseAddrPort(sample.Endpoint)
			if err != nil || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() ||
				endpoint.Addr().IsMulticast() ||
				endpoint.Addr().Zone() != "" {
				return invalid
			}
		}
		switch sample.Path {
		case "", "unknown", PathDirect, PathRelay:
		default:
			return invalid
		}
	}
	return nil
}

func telemetryDeviceID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}

	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' ||
			r == '_' ||
			r == '.' {
			continue
		}

		return false
	}

	return true
}
