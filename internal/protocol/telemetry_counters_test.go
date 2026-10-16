package protocol

import "testing"

func TestTelemetrySeparatesUnobservedCountersFromMeasuredZero(t *testing.T) {
	report := TelemetryReport{
		Generation:   1,
		Sequence:     1,
		RuntimeID:    "bc6603d1-5985-45d3-a22b-756ff04e8800",
		State:        RuntimeRunning,
		Observations: []PeerObservation{{DeviceID: "client-1"}},
	}

	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}

	report.Observations[0].RXBytes = 10

	if err := report.Validate(); err == nil {
		t.Fatal("unobserved traffic count accepted")
	}

	report.Observations[0].CountersAvailable = true

	if err := report.Validate(); err != nil {
		t.Fatalf("measured count rejected: %v", err)
	}

	report.Observations[0].RXBytes = 0

	if err := report.Validate(); err != nil {
		t.Fatalf("measured zero rejected: %v", err)
	}
}
