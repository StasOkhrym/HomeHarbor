package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

// ReportRuntimeShutdown is a bounded best-effort final observation after owned
// cleanup and worker joins. It never restores or applies a network snapshot.
// A heartbeat drains the ordered report; it is not a durable telemetry ack.
func ReportRuntimeShutdown(ctx context.Context, cfg CoordinationConfig) error {
	if cfg.Telemetry == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	report, err := cfg.Telemetry.Snapshot(ctx)
	if err != nil {
		return err
	}
	if report.State != protocol.RuntimeStopped && report.State != protocol.RuntimeFailed {
		return errors.New("runtime cleanup must complete before shutdown report")
	}

	credential := cfg.Credential
	if cfg.Leases != nil {
		lease, err := cfg.Leases.Current(ctx)
		if err != nil {
			return err
		}
		if lease.DeviceID != cfg.DeviceID || !lease.ExpiresAt.After(time.Now()) {
			return errors.New("invalid shutdown credential lease")
		}

		credential = lease.Credential
		var expire context.CancelFunc
		ctx, expire = context.WithDeadline(ctx, lease.ExpiresAt)
		defer expire()
	}

	if credential == "" || cfg.DeviceID == "" {
		return errors.New("shutdown credential and device required")
	}

	header := make(http.Header)
	header.Set("Authorization", "Bearer "+credential)

	c, _, err := websocket.Dial(
		ctx,
		cfg.URL,
		&websocket.DialOptions{
			HTTPClient:      cfg.HTTPClient,
			HTTPHeader:      header,
			CompressionMode: websocket.CompressionDisabled,
		},
	)
	if err != nil {
		return err
	}
	defer func() { _ = c.CloseNow() }()

	c.SetReadLimit(64 << 10)

	if err := wsjson.Write(
		ctx,
		c,
		protocol.Hello{
			Versions: []uint16{protocol.CurrentVersion},
			Capabilities: []string{
				protocol.CapabilityUDPPair,
				protocol.CapabilitySplitDNS,
				protocol.CapabilityTelemetry,
			},
			DeviceID: cfg.DeviceID,
		},
	); err != nil {
		return err
	}

	var welcome protocol.Welcome

	if err := wsjson.Read(ctx, c, &welcome); err != nil {
		return err
	}

	if welcome.Type != "welcome" || welcome.Protocol.Version != protocol.CurrentVersion ||
		!welcome.Protocol.Has(protocol.CapabilityUDPPair) {
		return errors.New("shutdown protocol negotiation failed")
	}
	if !welcome.Protocol.Has(protocol.CapabilityTelemetry) {
		return nil
	}

	report.Generation, report.Sequence = welcome.TelemetryGeneration, 1

	if err := report.Validate(); err != nil {
		return err
	}

	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}

	if err := wsjson.Write(
		ctx,
		c,
		protocol.Message{Type: "telemetry.report", Payload: payload},
	); err != nil {
		return err
	}

	if err := wsjson.Write(ctx, c, protocol.Message{Type: "heartbeat"}); err != nil {
		return err
	}

	for {
		var message protocol.Message

		if err := wsjson.Read(ctx, c, &message); err != nil {
			return err
		}

		if message.Type == "heartbeat.ack" {
			return nil
		}
		// Current heads may be queued ahead of the ack. Deliberately do not apply.
		if message.Type != "network.snapshot" {
			return errors.New("unexpected shutdown response")
		}
	}
}
