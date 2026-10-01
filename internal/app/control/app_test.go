package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
	"github.com/sokhrym/go-tunnels/internal/tunnel"
)

type snapshotReader struct {
	envelope snapshot.Envelope
}

func (r snapshotReader) Latest(
	context.Context,
) (snapshot.Envelope, error) {
	return r.envelope, nil
}

func TestAuthorizeRelayPeerRequiresSnapshotACLForGatewayRoute(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices: []snapshot.Device{
			{
				ID:                 "client",
				Role:               "client",
				WireGuardPublicKey: testWireGuardKey(t),
				OverlayAddress:     "100.64.0.2/32",
			},
			{
				ID:                 "gateway",
				Role:               "gateway",
				WireGuardPublicKey: testWireGuardKey(t),
				OverlayAddress:     "100.64.0.1/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway"}},
		Routes:   []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "192.168.50.0/24"}},
		ACL: []snapshot.ACLRule{
			{
				ID:             "allow-http",
				SourceDeviceID: "client",
				Destination:    "192.168.50.0/24",
				Protocol:       "tcp",
				PortFrom:       443,
				PortTo:         443,
			},
		},
	}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	reader := snapshotReader{envelope: envelope}
	client := devices.Device{ID: "client", Role: devices.RoleClient}
	gateway := devices.Device{ID: "gateway", Role: devices.RoleGateway}

	if !authorizeRelayPeer(context.Background(), reader, publicKey, "home", client, gateway) ||
		!authorizeRelayPeer(context.Background(), reader, publicKey, "home", gateway, client) {
		t.Fatal("authorized client/gateway pair was rejected")
	}
	if authorizeRelayPeer(
		context.Background(),
		reader,
		publicKey,
		"home",
		client,
		devices.Device{ID: "other", Role: devices.RoleGateway},
	) {
		t.Fatal("gateway absent from snapshot was authorized")
	}

	unsigned := reader.envelope
	unsigned.Signature[0] ^= 0xff

	if authorizeRelayPeer(
		context.Background(),
		snapshotReader{envelope: unsigned},
		publicKey,
		"home",
		client,
		gateway,
	) {
		t.Fatal("snapshot with an invalid signature was authorized")
	}
}

func TestAuthorizeRelayPeerRejectsSnapshotRoleMismatch(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices: []snapshot.Device{
			{
				ID:                 "client",
				Role:               "gateway",
				WireGuardPublicKey: testWireGuardKey(t),
				OverlayAddress:     "100.64.0.2/32",
			},
			{
				ID:                 "gateway",
				Role:               "gateway",
				WireGuardPublicKey: testWireGuardKey(t),
				OverlayAddress:     "100.64.0.1/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway"}},
		Routes:   []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "192.168.50.0/24"}},
		ACL: []snapshot.ACLRule{
			{
				ID:             "allow-http",
				SourceDeviceID: "client",
				Destination:    "192.168.50.0/24",
				Protocol:       "tcp",
				PortFrom:       443,
				PortTo:         443,
			},
		},
	}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	if authorizeRelayPeer(
		context.Background(),
		snapshotReader{envelope: envelope},
		publicKey,
		"home",
		devices.Device{ID: "client", Role: devices.RoleClient},
		devices.Device{ID: "gateway", Role: devices.RoleGateway},
	) {
		t.Fatal("snapshot role mismatch was authorized")
	}
}

func testWireGuardKey(t *testing.T) string {
	t.Helper()

	identity, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	return identity.PublicKey
}
