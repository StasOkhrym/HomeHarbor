package node

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
	"github.com/StasOkhrym/homeharbor/internal/tunnel"
)

type publicStatsReader struct {
	peers map[string]PeerStatistics
	err   error
}

func (r publicStatsReader) Read(context.Context) (map[string]PeerStatistics, error) {
	return r.peers, r.err
}

func telemetryTopology(t *testing.T) (snapshot.NetworkSnapshot, tunnel.Identity, tunnel.Identity) {
	t.Helper()

	gateway, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	client, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	return snapshot.NetworkSnapshot{NetworkID: "home", Revision: 7, Devices: []snapshot.Device{
		{
			ID:                 "gateway",
			Role:               "gateway",
			WireGuardPublicKey: gateway.PublicKey,
			OverlayAddress:     "100.64.0.1/32",
		},
		{
			ID:                 "client",
			Role:               "client",
			WireGuardPublicKey: client.PublicKey,
			OverlayAddress:     "100.64.0.2/32",
		},
	}, Gateways: []snapshot.Gateway{{DeviceID: "gateway"}}, Routes: []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "10.10.0.0/24"}}}, gateway, client
}

func TestRuntimeTelemetryScopesPeerStatisticsAndKeepsRuntimeIDAcrossSnapshots(t *testing.T) {
	value, gateway, client := telemetryTopology(t)

	foreign, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	reader := publicStatsReader{peers: map[string]PeerStatistics{
		client.PublicKey: {
			RXBytes:           10,
			TXBytes:           20,
			LastHandshakeUnix: time.Now().Unix(),
			Endpoint:          "127.0.0.1:51820",
		},
		foreign.PublicKey: {RXBytes: 9999, TXBytes: 9999, Endpoint: "192.0.2.80:1234"},
	}}
	path := protocol.PathRelay
	owner, err := NewRuntimeTelemetry(
		TelemetryConfig{
			DeviceID:     "gateway",
			Role:         "gateway",
			Statistics:   reader,
			PathDeviceID: "client",
			SelectedPath: func() protocol.Path { return path },
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	owner.Applied(value)

	report, err := owner.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if report.State != protocol.RuntimeRunning || report.AppliedRevision != 7 ||
		len(report.Observations) != 2 ||
		report.Observations[0].DeviceID != "gateway" ||
		report.Observations[0].RXBytes != 10 ||
		!report.Observations[0].CountersAvailable ||
		report.Observations[1].DeviceID != "client" ||
		report.Observations[1].Path != protocol.PathRelay {
		t.Fatalf("unscoped/missing runtime report: %+v", report)
	}

	data, _ := json.Marshal(report)

	if strings.Contains(string(data), foreign.PublicKey) ||
		strings.Contains(string(data), gateway.PrivateKey) ||
		strings.Contains(string(data), "192.0.2.80") {
		t.Fatalf("private/unrelated statistics leaked: %s", data)
	}

	value.Revision = 8

	owner.Applied(value)
	path = protocol.PathDirect

	next, err := owner.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if next.RuntimeID != report.RuntimeID || next.RuntimeID == "" || next.AppliedRevision != 8 ||
		next.Observations[1].Path != protocol.PathDirect {
		t.Fatalf("control revision changed VPN lifetime/path: %+v", next)
	}
}

func TestRuntimeTelemetryUnavailableStatisticsStayUnknown(t *testing.T) {
	value, _, _ := telemetryTopology(t)

	owner, err := NewRuntimeTelemetry(
		TelemetryConfig{
			DeviceID:   "client",
			Role:       "client",
			Statistics: publicStatsReader{err: errors.New("SECRET_STATS_FAILURE")},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	owner.Applied(value)

	report, err := owner.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if report.State != protocol.RuntimeRunning || len(report.Observations) != 1 ||
		report.Observations[0].CountersAvailable ||
		report.Observations[0].RXBytes != 0 ||
		report.Observations[0].LastHandshakeUnix != 0 {
		t.Fatalf("statistics failure became fictitious counters/connectivity: %+v", report)
	}

	data, _ := json.Marshal(report)

	if strings.Contains(string(data), "SECRET") {
		t.Fatal("statistics error leaked")
	}
}

func TestRuntimeTelemetryRemovalAndFailureKeepActualAppliedRevision(t *testing.T) {
	value, _, _ := telemetryTopology(t)

	owner, err := NewRuntimeTelemetry(TelemetryConfig{DeviceID: "client", Role: "client"})
	if err != nil {
		t.Fatal(err)
	}

	owner.Applied(value)
	owner.Failed()
	report, _ := owner.Snapshot(t.Context())

	if report.State != protocol.RuntimeFailed || report.AppliedRevision != 7 {
		t.Fatalf("failure invented applied state: %+v", report)
	}

	value.Revision = 8
	value.Devices = value.Devices[:1]

	owner.Applied(value)
	report, _ = owner.Snapshot(t.Context())

	if report.State != protocol.RuntimeStopped || report.AppliedRevision != 8 ||
		len(report.Observations) != 1 {
		t.Fatalf("verified removal retained running state: %+v", report)
	}
}
