package coordination

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/telemetry"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

// TelemetryCollector receives authenticated principals and server-issued sessions.
// An unavailable collector never advertises telemetry support to a client.
type TelemetryCollector interface {
	Begin(context.Context, devices.Device) (telemetry.Session, error)
	Report(context.Context, telemetry.Session, protocol.TelemetryReport) error
}

func (h *Handler) admitTelemetry(
	ctx context.Context,
	device devices.Device,
	negotiated *protocol.Negotiated,
) telemetry.Session {
	if !negotiated.Has(protocol.CapabilityTelemetry) {
		return telemetry.Session{}
	}

	if h.Telemetry != nil {
		session, err := h.Telemetry.Begin(ctx, device)
		if err == nil && session.Generation > 0 {
			return session
		}
	}

	// Telemetry is optional: a storage failure must not change VPN admission.
	capabilities := make([]string, 0, len(negotiated.Capabilities))
	for _, capability := range negotiated.Capabilities {
		if capability != protocol.CapabilityTelemetry {
			capabilities = append(capabilities, capability)
		}
	}

	negotiated.Capabilities = capabilities

	return telemetry.Session{}
}

func (h *Handler) receiveTelemetry(
	ctx context.Context,
	session telemetry.Session,
	payload json.RawMessage,
) error {
	if h.Telemetry == nil || session.Generation == 0 {
		return telemetry.ErrUnauthorized
	}

	var report protocol.TelemetryReport
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || report.Validate() != nil {
		return telemetry.ErrInvalidReport
	}
	if report.Generation != session.Generation {
		return telemetry.ErrStaleReport
	}

	return h.Telemetry.Report(ctx, session, report)
}

// Invalid input ends admission. Temporary observation storage failure simply
// leaves the previous observation to age out; it must not stop VPN coordination.
func telemetryPolicyViolation(err error) bool {
	return errors.Is(err, telemetry.ErrInvalidReport) ||
		errors.Is(err, telemetry.ErrUnauthorized) ||
		errors.Is(err, telemetry.ErrStaleReport)
}
