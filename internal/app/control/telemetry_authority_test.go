package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

func TestTelemetryObservesSignedPeersWithoutGrantingRelayTraffic(t *testing.T) {
	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	gateway := devices.Device{
		ID:                 "gateway",
		Role:               devices.RoleGateway,
		Status:             devices.StatusActive,
		WireGuardPublicKey: testWireGuardKey(t),
	}
	client := devices.Device{
		ID:                 "client",
		Role:               devices.RoleClient,
		Status:             devices.StatusRevoked,
		WireGuardPublicKey: testWireGuardKey(t),
	}
	value := snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1, Devices: []snapshot.Device{
		{
			ID:                 gateway.ID,
			Role:               "gateway",
			WireGuardPublicKey: gateway.WireGuardPublicKey,
			OverlayAddress:     "100.64.0.1/32",
		},
		{
			ID:                 client.ID,
			Role:               "client",
			WireGuardPublicKey: client.WireGuardPublicKey,
			OverlayAddress:     "100.64.0.2/32",
		},
	}, Gateways: []snapshot.Gateway{{DeviceID: gateway.ID}}, Routes: []snapshot.Route{{ID: "lan", GatewayID: gateway.ID, Prefix: "192.168.50.0/24"}}}

	envelope, err := snapshot.Sign(value, private, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	reader := snapshotReader{envelope: envelope}

	if authorizeRelayPeer(t.Context(), reader, root, "home", gateway, client) {
		t.Fatal("absent ACL unexpectedly grants traffic")
	}
	if !authorizeTelemetryPeer(t.Context(), reader, root, "home", gateway, client) {
		t.Fatal("actual signed peer cannot be observed without ACL traffic grant")
	}

	foreign := client
	foreign.ID = "foreign"

	if authorizeTelemetryPeer(t.Context(), reader, root, "home", gateway, foreign) {
		t.Fatal("unsigned peer allowed")
	}

	wrongKey := client

	wrongKey.WireGuardPublicKey = testWireGuardKey(t)

	if authorizeTelemetryPeer(t.Context(), reader, root, "home", gateway, wrongKey) {
		t.Fatal("unsigned key substitution allowed")
	}
	if authorizeTelemetryPeer(t.Context(), reader, root, "home", client, gateway) {
		t.Fatal("client can report another subject")
	}

	damaged := envelope
	damaged.Signature = append([]byte(nil), envelope.Signature...)
	damaged.Signature[0] ^= 0xff

	if authorizeTelemetryPeer(
		t.Context(),
		snapshotReader{envelope: damaged},
		root,
		"home",
		gateway,
		client,
	) {
		t.Fatal("invalid signature allowed")
	}
}
