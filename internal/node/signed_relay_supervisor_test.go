package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
	"github.com/StasOkhrym/homeharbor/internal/tunnel"
)

type signedRelayEndpoints struct{}

func (signedRelayEndpoints) SetPeerEndpoint(context.Context, string, netip.AddrPort) error {
	return nil
}
func (signedRelayEndpoints) ClearPeerEndpoint(context.Context, string) error { return nil }

func signedRelayFixture(t *testing.T) (SignedRelayConfig, snapshot.NetworkSnapshot) {
	t.Helper()

	gateway, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	client, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	root := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	cfg := SignedRelayConfig{
		NetworkID:        "home",
		RootPublicKey:    root,
		DeviceID:         "gateway",
		RelayURL:         "wss://relay.example.test/relay/udp",
		WireGuardAddress: "127.0.0.1:51820",
		Endpoints:        signedRelayEndpoints{},
		Issue: func(context.Context, string, string) (RelaySession, error) {
			return RelaySession{}, errors.New("offline")
		},
	}
	value := snapshot.NetworkSnapshot{
		NetworkID: "home", Revision: 1,
		Devices: []snapshot.Device{
			{
				ID:                 "gateway",
				Role:               "gateway",
				WireGuardPublicKey: gateway.PublicKey,
				OverlayAddress:     "10.243.0.2/32",
			},
			{
				ID:                 "client",
				Role:               "client",
				WireGuardPublicKey: client.PublicKey,
				OverlayAddress:     "10.243.0.1/32",
			},
		}, Gateways: []snapshot.Gateway{{DeviceID: "gateway", Name: "Home"}},
	}

	return cfg, value
}

func TestSignedRelaySupervisorOwnsOnlySignedClientsAndJoinsRemoval(t *testing.T) {
	cfg, value := signedRelayFixture(t)
	owner, err := NewSignedRelaySupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan SignedRelayPeer, 4)
	var mu sync.Mutex
	var sockets []*net.UDPConn
	owner.runPeer = func(ctx context.Context, pair SignedRelayPeer) error {
		socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return err
		}
		defer func() { _ = socket.Close() }()

		mu.Lock()
		sockets = append(sockets, socket)

		mu.Unlock()
		started <- pair
		<-ctx.Done()
		return nil
	}

	if err := owner.Prepare(context.Background(), value); err != nil {
		t.Fatal(err)
	}

	select {
	case <-started:
		t.Fatal("prepare opened a transport")
	default:
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- owner.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("supervisor did not join")
		}
	})
	operation, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()

	if err := owner.Apply(operation, value); err != nil {
		t.Fatal(err)
	}

	var pair SignedRelayPeer
	select {
	case pair = <-started:
	case <-operation.Done():
		t.Fatal("client worker missing")
	}

	want, err := protocol.RelayPairSessionID("home", cfg.RootPublicKey, "gateway", "client")
	if err != nil {
		t.Fatal(err)
	}

	if pair.DeviceID != "client" || pair.SessionID != want ||
		pair.PublicKey != value.Devices[1].WireGuardPublicKey {
		t.Fatal("worker is not signed-peer bound")
	}

	if err := owner.Apply(operation, value); err != nil {
		t.Fatal(err)
	}

	select {
	case <-started:
		t.Fatal("unchanged revision replaced transport")
	default:
	}

	conflict := cloneNetworkSnapshot(value)
	conflict.Routes = []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "192.168.50.0/24"}}

	if err := owner.Apply(operation, conflict); err == nil {
		t.Fatal("equal revision conflict")
	}

	removed := cloneNetworkSnapshot(value)
	removed.Revision = 2
	removed.Devices = removed.Devices[:1]

	if err := owner.Apply(operation, removed); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	owned := append([]*net.UDPConn(nil), sockets...)

	mu.Unlock()
	for _, socket := range owned {
		if _, err := socket.WriteToUDP(
			[]byte("late"),
			socket.LocalAddr().(*net.UDPAddr),
		); !errors.Is(
			err,
			net.ErrClosed,
		) {
			t.Fatal("removed worker socket survived apply")
		}
	}

	if err := owner.Apply(operation, value); err == nil {
		t.Fatal("rollback accepted")
	}

	select {
	case <-started:
		t.Fatal("rollback started worker")
	default:
	}
}

func TestSignedRelaySupervisorJoinsBeforeRekeyAndStop(t *testing.T) {
	cfg, value := signedRelayFixture(t)
	owner, err := NewSignedRelaySupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan string, 3)
	cleanup := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseOld := func() { releaseOnce.Do(func() { close(release) }) }
	owner.runPeer = func(ctx context.Context, pair SignedRelayPeer) error {
		started <- pair.PublicKey
		<-ctx.Done()
		if pair.PublicKey == value.Devices[1].WireGuardPublicKey {
			close(cleanup)
			<-release
		}

		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- owner.Run(ctx) }()
	t.Cleanup(func() {
		releaseOld()
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("supervisor join")
		}
	})
	operation, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()

	if err := owner.Apply(operation, value); err != nil {
		t.Fatal(err)
	}

	select {
	case <-started:
	case <-operation.Done():
		t.Fatal("initial worker")
	}

	updated := cloneNetworkSnapshot(value)
	updated.Revision = 2

	key, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	updated.Devices[1].WireGuardPublicKey = key.PublicKey
	applied := make(chan error, 1)
	go func() { applied <- owner.Apply(operation, updated) }()
	select {
	case <-cleanup:
	case <-operation.Done():
		t.Fatal("old worker not canceled")
	}

	select {
	case <-started:
		t.Fatal("replacement raced old cleanup")
	default:
	}

	releaseOld()

	if err := <-applied; err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-started:
		if got != key.PublicKey {
			t.Fatal("wrong replacement")
		}
	case <-operation.Done():
		t.Fatal("replacement missing")
	}

	if err := owner.Close(operation); err != nil {
		t.Fatal(err)
	}

	if err := owner.Apply(operation, updated); err == nil {
		t.Fatal("closed owner resurrected worker")
	}
}

func TestSignedRelaySupervisorInvalidTopologyHasNoSideEffects(t *testing.T) {
	cfg, value := signedRelayFixture(t)
	owner, err := NewSignedRelaySupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, mutate := range []func(*snapshot.NetworkSnapshot){
		func(v *snapshot.NetworkSnapshot) { v.NetworkID = "foreign" },
		func(v *snapshot.NetworkSnapshot) { v.Devices[0].Role = "client" },
		func(v *snapshot.NetworkSnapshot) { v.Devices[1].WireGuardPublicKey = "invalid" },
		func(v *snapshot.NetworkSnapshot) { v.Devices = append(v.Devices, v.Devices[1]) },
	} {
		bad := cloneNetworkSnapshot(value)

		mutate(&bad)

		if err := owner.Prepare(context.Background(), bad); err == nil {
			t.Fatal("invalid topology prepared")
		}
	}
}

func TestSignedRelaySupervisorDoesNotReserveAnOtherwiseValidDeviceID(t *testing.T) {
	cfg, _ := signedRelayFixture(t)
	cfg.DeviceID = "validation-peer"

	if _, err := NewSignedRelaySupervisor(cfg); err != nil {
		t.Fatal("valid gateway identity collides with validation implementation:", err)
	}
}

func TestSignedRelaySupervisorReportsCleanupFailureAfterJoiningWorkers(t *testing.T) {
	cfg, value := signedRelayFixture(t)
	owner, err := NewSignedRelaySupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cleanupFailure := errors.New("endpoint cleanup failed")
	started := make(chan struct{})
	owner.runPeer = func(ctx context.Context, _ SignedRelayPeer) error {
		close(started)
		<-ctx.Done()
		return cleanupFailure
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- owner.Run(ctx) }()
	operation, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()

	if err := owner.Apply(operation, value); err != nil {
		t.Fatal(err)
	}

	select {
	case <-started:
	case <-operation.Done():
		t.Fatal("worker did not start")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, cleanupFailure) {
			t.Fatal("cleanup failure hidden:", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not join")
	}
}
