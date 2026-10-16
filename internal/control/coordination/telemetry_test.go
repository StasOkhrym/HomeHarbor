package coordination

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/telemetry"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type telemetryCapture struct {
	began       chan devices.Device
	reports     chan protocol.TelemetryReport
	reportError error
}

func (c *telemetryCapture) Begin(
	_ context.Context,
	device devices.Device,
) (telemetry.Session, error) {
	c.began <- device
	return telemetry.Session{Generation: 41}, nil
}

func (c *telemetryCapture) Report(
	_ context.Context,
	session telemetry.Session,
	report protocol.TelemetryReport,
) error {
	if session.Generation != 41 {
		return telemetry.ErrStaleReport
	}
	if c.reportError != nil {
		return c.reportError
	}

	c.reports <- report
	return nil
}

func TestCoordinationTelemetryRequiresNegotiationAndServerGeneration(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		negotiate, available bool
		generation           uint64
		wantReport           bool
	}{
		{"enabled", true, true, 41, true}, {"no capability", false, true, 41, false}, {"foreign generation", true, true, 42, false}, {"not configured", true, false, 41, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := &telemetryCapture{
				began:   make(chan devices.Device, 1),
				reports: make(chan protocol.TelemetryReport, 1),
			}
			handler := NewHandler(coordinationAuthStub{}, nil, coordinationSnapshotStub{}, nil, nil)
			if tc.available {
				handler.Telemetry = capture
			}

			server := httptest.NewServer(handler)
			defer server.Close()

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()

			connection, _, err := websocket.Dial(
				ctx,
				"ws"+strings.TrimPrefix(server.URL, "http"),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = connection.CloseNow() }()

			capabilities := []string{protocol.CapabilityUDPPair}
			if tc.negotiate {
				capabilities = append(capabilities, protocol.CapabilityTelemetry)
			}

			if err := wsjson.Write(
				ctx,
				connection,
				protocol.Hello{
					Versions:     []uint16{protocol.CurrentVersion},
					Capabilities: capabilities,
					DeviceID:     "device-1",
				},
			); err != nil {
				t.Fatal(err)
			}

			var welcome protocol.Welcome

			if err := wsjson.Read(ctx, connection, &welcome); err != nil {
				t.Fatal(err)
			}

			enabled := tc.negotiate && tc.available

			if welcome.Protocol.Has(protocol.CapabilityTelemetry) != enabled ||
				(enabled && welcome.TelemetryGeneration != 41) ||
				(!enabled && welcome.TelemetryGeneration != 0) {
				t.Fatalf("incorrect telemetry admission: %+v", welcome)
			}

			var snapshot protocol.Message

			if err := wsjson.Read(ctx, connection, &snapshot); err != nil {
				t.Fatal(err)
			}

			report := protocol.TelemetryReport{
				Generation:   tc.generation,
				Sequence:     1,
				RuntimeID:    "bc6603d1-5985-45d3-a22b-756ff04e8800",
				State:        protocol.RuntimeRunning,
				Observations: []protocol.PeerObservation{{DeviceID: "device-1"}},
			}

			payload, _ := json.Marshal(report)

			if err := wsjson.Write(
				ctx,
				connection,
				protocol.Message{Type: "telemetry.report", Payload: payload},
			); err != nil {
				t.Fatal(err)
			}

			if tc.wantReport {
				select {
				case got := <-capture.reports:
					if got.RuntimeID != report.RuntimeID {
						t.Fatal("runtime identity changed")
					}
				case <-ctx.Done():
					t.Fatal("negotiated report not delivered")
				}

				select {
				case device := <-capture.began:
					if device.ID != "device-1" {
						t.Fatal("not authenticated reporter")
					}
				default:
					t.Fatal("no server generation allocation")
				}
			} else {
				var message protocol.Message

				if err := wsjson.Read(
					ctx,
					connection,
					&message,
				); websocket.CloseStatus(
					err,
				) != websocket.StatusPolicyViolation {
					t.Fatalf("invalid telemetry not rejected: %v %+v", err, message)
				}

				select {
				case <-capture.reports:
					t.Fatal("unnegotiated/forged report delivered")
				default:
				}
			}
		})
	}
}

func TestTelemetryStoreFailureDoesNotDropCoordination(t *testing.T) {
	capture := &telemetryCapture{
		began:       make(chan devices.Device, 1),
		reports:     make(chan protocol.TelemetryReport, 1),
		reportError: errors.New("SECRET_STORAGE_ERROR"),
	}
	handler := NewHandler(coordinationAuthStub{}, nil, coordinationSnapshotStub{}, nil, nil)
	handler.Telemetry = capture
	server := httptest.NewServer(handler)
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.CloseNow() }()

	if err := wsjson.Write(
		ctx,
		connection,
		protocol.Hello{
			Versions:     []uint16{protocol.CurrentVersion},
			Capabilities: []string{protocol.CapabilityUDPPair, protocol.CapabilityTelemetry},
			DeviceID:     "device-1",
		},
	); err != nil {
		t.Fatal(err)
	}

	var welcome protocol.Welcome

	if err := wsjson.Read(ctx, connection, &welcome); err != nil {
		t.Fatal(err)
	}

	var message protocol.Message

	if err := wsjson.Read(ctx, connection, &message); err != nil {
		t.Fatal(err)
	}

	report := protocol.TelemetryReport{
		Generation:   41,
		Sequence:     1,
		RuntimeID:    "bc6603d1-5985-45d3-a22b-756ff04e8800",
		State:        protocol.RuntimeRunning,
		Observations: []protocol.PeerObservation{{DeviceID: "device-1"}},
	}

	payload, _ := json.Marshal(report)

	if err := wsjson.Write(
		ctx,
		connection,
		protocol.Message{Type: "telemetry.report", Payload: payload},
	); err != nil {
		t.Fatal(err)
	}

	if err := wsjson.Write(ctx, connection, protocol.Message{Type: "heartbeat"}); err != nil {
		t.Fatal(err)
	}

	if err := wsjson.Read(
		ctx,
		connection,
		&message,
	); err != nil ||
		message.Type != "heartbeat.ack" {
		t.Fatalf("optional telemetry failure dropped control connection: %v %+v", err, message)
	}
}
