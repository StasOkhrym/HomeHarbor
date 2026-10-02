package node

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	controlprotocol "github.com/StasOkhrym/homeharbor/internal/protocol"
)

type endpointRecorder struct {
	mu    sync.Mutex
	set   []netip.AddrPort
	clear int
}

func (r *endpointRecorder) SetPeerEndpoint(
	_ context.Context,
	_ string,
	endpoint netip.AddrPort,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.set = append(r.set, endpoint)

	return nil
}

func (r *endpointRecorder) ClearPeerEndpoint(_ context.Context, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.clear++
	return nil
}

func (r *endpointRecorder) state() (setCount, clearCount int, endpoints []netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.set), r.clear, append([]netip.AddrPort(nil), r.set...)
}

type handshakeProbeStub struct {
	results []error
}

type relayBridgeStub struct {
	started chan struct{}
}

func (b *relayBridgeStub) Run(ctx context.Context) error {
	close(b.started)
	<-ctx.Done()
	return nil
}

func (p *handshakeProbeStub) HandshakeTime(context.Context, string) (time.Time, error) {
	return time.Time{}, nil
}

func (p *handshakeProbeStub) WaitForHandshake(context.Context, string, time.Time) error {
	if len(p.results) == 0 {
		return nil
	}

	err := p.results[0]
	p.results = p.results[1:]

	return err
}

func TestCandidatePathManagerSelectsHighestPriorityHandshake(t *testing.T) {
	updater := &endpointRecorder{}
	probe := &handshakeProbeStub{results: []error{errors.New("first candidate timed out"), nil}}
	selector := controlprotocol.NewPathSelector()
	manager, err := NewCandidatePathManager(
		"client",
		"gateway",
		validPeerKey,
		updater,
		selector,
		probe,
	)
	if err != nil {
		t.Fatal(err)
	}
	update := controlprotocol.CandidateUpdate{
		SourceDeviceID:      "gateway",
		DestinationDeviceID: "client",
		Candidates: []controlprotocol.Candidate{
			{Type: controlprotocol.CandidateHost, Address: "192.168.1.20:51820", Priority: 100},
			{
				Type:     controlprotocol.CandidateServerReflexive,
				Address:  "203.0.113.20:51820",
				Priority: 200,
			},
		},
	}
	if err := manager.HandleCandidateUpdate(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	if got := selector.Current(); got != controlprotocol.PathDirect {
		t.Fatalf("path=%q, want direct", got)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.20:51820"),
		netip.MustParseAddrPort("192.168.1.20:51820"),
	}
	_, _, endpoints := updater.state()
	if len(endpoints) != len(want) || endpoints[0] != want[0] || endpoints[1] != want[1] {
		t.Fatalf("endpoints=%v, want %v", endpoints, want)
	}
}

func TestCandidatePathManagerFallsBackAfterEveryDirectHandshakeFails(t *testing.T) {
	updater := &endpointRecorder{}
	probe := &handshakeProbeStub{results: []error{errors.New("timeout")}}
	selector := controlprotocol.NewPathSelector()
	manager, err := NewCandidatePathManager(
		"client",
		"gateway",
		validPeerKey,
		updater,
		selector,
		probe,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.HandleCandidateUpdate(
		context.Background(),
		controlprotocol.CandidateUpdate{
			SourceDeviceID:      "gateway",
			DestinationDeviceID: "client",
			Candidates: []controlprotocol.Candidate{
				{Type: controlprotocol.CandidateHost, Address: "192.168.1.20:51820", Priority: 100},
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if selector.Current() != controlprotocol.PathRelay {
		t.Fatalf("path=%q, want relay", selector.Current())
	}
	_, clearCount, _ := updater.state()
	if clearCount != 1 {
		t.Fatalf("clear calls=%d, want 1", clearCount)
	}
}

func TestCandidatePathManagerRejectsUpdateForAnotherLocalDevice(t *testing.T) {
	manager, err := NewCandidatePathManager(
		"client",
		"gateway",
		validPeerKey,
		&endpointRecorder{},
		controlprotocol.NewPathSelector(),
		&handshakeProbeStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.HandleCandidateUpdate(
		context.Background(),
		controlprotocol.CandidateUpdate{
			SourceDeviceID:      "gateway",
			DestinationDeviceID: "other",
			Candidates: []controlprotocol.Candidate{
				{Type: controlprotocol.CandidateHost, Address: "192.168.1.20:51820", Priority: 100},
			},
		},
	); err == nil {
		t.Fatal("candidate update for another local device was accepted")
	}
	if err := manager.HandleCandidateUpdate(
		context.Background(),
		controlprotocol.CandidateUpdate{
			SourceDeviceID:      "other",
			DestinationDeviceID: "client",
			Candidates: []controlprotocol.Candidate{
				{Type: controlprotocol.CandidateHost, Address: "192.168.1.20:51820", Priority: 100},
			},
		},
	); err == nil {
		t.Fatal("candidate update from another peer was accepted")
	}
}

func TestRelayWatcherFollowsDirectAndFallbackPathChanges(t *testing.T) {
	updater := &endpointRecorder{}
	selector := controlprotocol.NewPathSelector()
	bridge := &relayBridgeStub{started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runKernelRelayWithPathSelector(ctx, bridge, KernelRelayConfig{PeerPublicKey: validPeerKey, EndpointUpdater: updater, PathSelector: selector}, netip.MustParseAddrPort("127.0.0.1:51821"))
	}()
	select {
	case <-bridge.started:
	case <-time.After(time.Second):
		t.Fatal("relay bridge did not start")
	}
	deadline := time.Now().Add(time.Second)
	setCount, _, _ := updater.state()
	for setCount == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		setCount, _, _ = updater.state()
	}
	setCount, _, endpoints := updater.state()
	if setCount != 1 {
		t.Fatalf("initial relay endpoint updates=%v", endpoints)
	}
	selector.DirectHandshakeSucceeded()
	time.Sleep(20 * time.Millisecond)
	setCount, _, endpoints = updater.state()
	if setCount != 1 {
		t.Fatalf("direct path caused relay endpoint overwrite: %v", endpoints)
	}
	selector.DirectFailed()
	deadline = time.Now().Add(time.Second)
	setCount, _, _ = updater.state()
	for setCount < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		setCount, _, _ = updater.state()
	}
	setCount, _, endpoints = updater.state()
	if setCount != 2 {
		t.Fatalf("relay fallback endpoint updates=%v", endpoints)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay watcher did not stop")
	}
	_, clearCount, _ := updater.state()
	if clearCount != 1 {
		t.Fatalf("clear calls=%d, want 1", clearCount)
	}
}

func TestParseDirectCandidatesRejectsUnspecifiedAddress(t *testing.T) {
	if _, err := ParseDirectCandidates("0.0.0.0:51820"); err == nil {
		t.Fatal("unspecified direct candidate was accepted")
	}

	candidates, err := ParseDirectCandidates("192.168.1.20:51820,203.0.113.20:51821")

	if err != nil || len(candidates) != 2 || candidates[0].Priority != 2 ||
		candidates[1].Priority != 1 {
		t.Fatalf("candidates=%#v error=%v", candidates, err)
	}
}

func TestCandidateSetPublishesRelayObservedEndpointOnce(t *testing.T) {
	set := NewCandidateSet(
		[]controlprotocol.Candidate{
			{Type: controlprotocol.CandidateHost, Address: "192.168.1.20:51820", Priority: 100},
		},
	)

	set.SetObservedEndpoint(netip.MustParseAddrPort("203.0.113.20:45000"))
	select {
	case <-set.Changes():
	case <-time.After(time.Second):
		t.Fatal("candidate change was not signaled")
	}

	set.SetObservedEndpoint(netip.MustParseAddrPort("203.0.113.20:45000"))
	select {
	case <-set.Changes():
		t.Fatal("duplicate candidate change was signaled")
	default:
	}

	candidates := set.Snapshot()

	if len(candidates) != 2 || candidates[1].Type != controlprotocol.CandidateServerReflexive ||
		candidates[1].Priority != 200 {
		t.Fatalf("candidates=%#v", candidates)
	}
}

const validPeerKey = "6N6R6wQW8vJQeWk7U5d4x1jY5H6V5n3a9Q2w8e7r6tI="
