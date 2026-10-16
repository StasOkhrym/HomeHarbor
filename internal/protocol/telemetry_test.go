package protocol

import (
	"encoding/json"
	"math"
	"testing"
)

func TestTelemetryIsOptionalDuringNegotiation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		hello := Hello{
			Versions:     []uint16{CurrentVersion},
			Capabilities: []string{CapabilityUDPPair},
		}
		if enabled {
			hello.Capabilities = append(hello.Capabilities, CapabilityTelemetry)
		}

		negotiated, err := Negotiate(hello)

		if err != nil || negotiated.Has(CapabilityTelemetry) != enabled {
			t.Fatalf("telemetry=%t negotiated=%+v error=%v", enabled, negotiated, err)
		}
	}
}

func TestTelemetryRejectsMalformedReports(t *testing.T) {
	valid := TelemetryReport{
		Generation: 1,
		Sequence:   1,
		RuntimeID:  "bc6603d1-5985-45d3-a22b-756ff04e8800",
		State:      RuntimeRunning,
		Observations: []PeerObservation{
			{
				DeviceID: "client-1",
				RXBytes:  12,
				TXBytes:  24,
				Endpoint: "127.0.0.1:51820",
				Path:     PathRelay,
			},
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []func(*TelemetryReport){
		func(r *TelemetryReport) { r.Sequence = 0 },
		func(r *TelemetryReport) { r.Generation = 0 },
		func(r *TelemetryReport) { r.RuntimeID = "SECRET_TOKEN" },
		func(r *TelemetryReport) { r.State = "connected and healthy" },
		func(r *TelemetryReport) { r.Observations = append(r.Observations, r.Observations[0]) },
		func(r *TelemetryReport) { r.Observations[0].RXBytes = math.MaxUint64 },
		func(r *TelemetryReport) { r.Observations[0].Endpoint = "Bearer SECRET" },
		func(r *TelemetryReport) { r.Observations[0].Path = "possibly-direct" },
		func(r *TelemetryReport) { r.Observations[0].LastHandshakeUnix = -1 },
	}
	for i, change := range cases {
		report := valid
		report.Observations = append([]PeerObservation(nil), valid.Observations...)
		change(&report)
		if err := report.Validate(); err == nil {
			t.Errorf("malformed report %d accepted", i)
		}
	}
	var negative TelemetryReport
	if err := json.Unmarshal(
		[]byte(`{"observations":[{"device_id":"client-1","rx_bytes":-1}]}`),
		&negative,
	); err == nil {
		t.Fatal("negative counter decoded")
	}
}
