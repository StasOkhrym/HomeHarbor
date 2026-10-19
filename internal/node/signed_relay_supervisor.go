package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type SignedRelayConfig struct {
	NetworkID        string
	RootPublicKey    ed25519.PublicKey
	DeviceID         string
	RelayURL         string
	WireGuardAddress string
	HTTPClient       *http.Client
	Endpoints        PeerEndpointUpdater
	Issue            func(context.Context, string, string) (RelaySession, error)
}

type SignedRelayPeer struct {
	DeviceID  string
	PublicKey string
	SessionID string
}

type signedRelayWorker struct {
	peer   SignedRelayPeer
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	err    error // Read only after done closes.
}

// SignedRelaySupervisor consumes topology already authenticated by coordination.
// It owns only per-client transport lifetime; the existing WG reconciler alone
// owns keys and prefixes. Prepare never opens sockets or obtains tickets.
type SignedRelaySupervisor struct {
	cfg       SignedRelayConfig
	op        sync.Mutex
	mu        sync.Mutex
	ready     chan struct{}
	readyOnce sync.Once
	fatal     chan error
	running   bool
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	current   *snapshot.NetworkSnapshot
	workers   map[string]*signedRelayWorker
	runPeer   func(context.Context, SignedRelayPeer) error
}

func NewSignedRelaySupervisor(cfg SignedRelayConfig) (*SignedRelaySupervisor, error) {
	validationPeer := "validation-peer"
	if cfg.DeviceID == validationPeer {
		validationPeer = "validation-other"
	}

	if _, err := protocol.RelayPairSessionID(
		cfg.NetworkID,
		cfg.RootPublicKey,
		cfg.DeviceID,
		validationPeer,
	); err != nil {
		return nil, errors.New("managed relay requires pinned network and gateway identity")
	}

	if err := protocol.ValidateRelayControlURL(cfg.RelayURL); err != nil {
		return nil, err
	}

	address, err := netip.ParseAddrPort(cfg.WireGuardAddress)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 || cfg.Endpoints == nil ||
		cfg.Issue == nil {
		return nil, errors.New(
			"managed relay requires loopback WireGuard address, endpoint owner and ticket issuer",
		)
	}

	cfg.RootPublicKey = append(ed25519.PublicKey(nil), cfg.RootPublicKey...)
	r := &SignedRelaySupervisor{
		cfg:     cfg,
		ready:   make(chan struct{}),
		fatal:   make(chan error, 1),
		workers: make(map[string]*signedRelayWorker),
	}
	r.runPeer = r.runManagedPeer

	return r, nil
}

func (r *SignedRelaySupervisor) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("managed relay supervisor already running")
	}
	if r.closed {
		r.mu.Unlock()
		return nil
	}

	r.running = true
	r.ctx, r.cancel = context.WithCancel(ctx)
	r.readyOnce.Do(func() { close(r.ready) })
	workerContext := r.ctx
	r.mu.Unlock()
	var result error
	select {
	case <-workerContext.Done():
	case result = <-r.fatal:
	}

	return errors.Join(result, r.Close(context.Background()))
}

func (r *SignedRelaySupervisor) Prepare(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	r.op.Lock()
	defer r.op.Unlock()

	_, err := r.plan(value)

	return err
}

func (r *SignedRelaySupervisor) plan(
	value snapshot.NetworkSnapshot,
) (map[string]SignedRelayPeer, error) {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, errors.New("managed relay supervisor is closed")
	}
	if value.NetworkID != r.cfg.NetworkID || value.Revision == 0 || len(value.Devices) > 64 {
		return nil, errors.New("invalid managed relay topology scope")
	}
	if r.current != nil && (value.Revision < r.current.Revision ||
		(value.Revision == r.current.Revision && snapshotFingerprint(value) != snapshotFingerprint(*r.current))) {
		return nil, errors.New("managed relay topology rollback or conflict")
	}

	var local *snapshot.Device
	keys := make(map[wgtypes.Key]bool)
	for i, device := range value.Devices {
		key, err := wgtypes.ParseKey(device.WireGuardPublicKey)
		if err != nil || key == (wgtypes.Key{}) || keys[key] ||
			(device.Role != "client" && device.Role != "gateway") {
			return nil, errors.New("invalid managed relay device identity")
		}

		keys[key] = true
		if device.ID == r.cfg.DeviceID {
			local = &value.Devices[i]
		}
	}

	peers, err := BuildWireGuardPeerConfigs(value, r.cfg.DeviceID)
	if errors.Is(err, ErrLocalDeviceMissing) {
		for _, gateway := range value.Gateways {
			if gateway.DeviceID == r.cfg.DeviceID {
				return nil, err
			}
		}

		return map[string]SignedRelayPeer{}, nil
	}
	if err != nil {
		return nil, err
	}
	if local == nil || local.Role != "gateway" {
		return nil, errors.New("managed relay local identity is not a gateway")
	}

	registered := false
	for _, gateway := range value.Gateways {
		if gateway.DeviceID == r.cfg.DeviceID {
			registered = true
		}
	}

	if !registered {
		return nil, errors.New("managed relay local gateway is not registered")
	}

	allowed := make(map[string]bool, len(peers))
	for _, peer := range peers {
		allowed[peer.PublicKey] = true
	}

	desired := make(map[string]SignedRelayPeer)
	for _, device := range value.Devices {
		if device.Role != "client" || !allowed[device.WireGuardPublicKey] {
			continue
		}

		id, err := protocol.RelayPairSessionID(
			r.cfg.NetworkID,
			r.cfg.RootPublicKey,
			r.cfg.DeviceID,
			device.ID,
		)
		if err != nil {
			return nil, err
		}

		desired[device.ID] = SignedRelayPeer{
			DeviceID:  device.ID,
			PublicKey: device.WireGuardPublicKey,
			SessionID: id,
		}
	}

	return desired, nil
}

func (r *SignedRelaySupervisor) Apply(ctx context.Context, value snapshot.NetworkSnapshot) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ready:
	}

	r.op.Lock()
	defer r.op.Unlock()

	desired, err := r.plan(value)
	if err != nil {
		return err
	}

	for id, worker := range r.workers {
		if peer, exists := desired[id]; exists && peer == worker.peer && worker.ctx.Err() == nil {
			continue
		}

		worker.cancel()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-worker.done:
		}

		delete(r.workers, id)
		if worker.err != nil {
			return worker.err
		}
	}

	for id, peer := range desired {
		if _, exists := r.workers[id]; exists {
			continue
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return errors.New("managed relay supervisor is closed")
		}

		workerCtx, cancel := context.WithCancel(r.ctx)
		worker := &signedRelayWorker{
			peer:   peer,
			ctx:    workerCtx,
			cancel: cancel,
			done:   make(chan struct{}),
		}
		r.workers[id] = worker
		r.mu.Unlock()
		go func() {
			defer close(worker.done)

			err := r.runPeer(workerCtx, peer)
			if workerCtx.Err() == nil {
				if err == nil {
					err = errors.New("managed relay worker exited unexpectedly")
				}

				worker.err = err
				select {
				case r.fatal <- err:
				default:
				}
			} else {
				worker.err = err
			}
		}()
	}

	copy := cloneNetworkSnapshot(value)
	r.current = &copy

	return nil
}

func (r *SignedRelaySupervisor) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}

	r.readyOnce.Do(func() { close(r.ready) })
	r.mu.Unlock()
	r.op.Lock()
	defer r.op.Unlock()

	for _, worker := range r.workers {
		worker.cancel()
	}

	var result error
	for id, worker := range r.workers {
		select {
		case <-ctx.Done():
			return errors.Join(result, ctx.Err())
		case <-worker.done:
		}

		result = errors.Join(result, worker.err)
		delete(r.workers, id)
	}

	return result
}

func (r *SignedRelaySupervisor) runManagedPeer(
	ctx context.Context,
	peer SignedRelayPeer,
) (result error) {
	fetch := func(ctx context.Context) (RelaySession, error) {
		operation, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		issued, err := r.cfg.Issue(operation, peer.SessionID, peer.DeviceID)
		if err != nil {
			return RelaySession{}, err
		}
		if issued.SessionID != peer.SessionID || issued.DeviceID != r.cfg.DeviceID ||
			issued.DestinationDeviceID != peer.DeviceID || issued.RelayTransport != protocol.CapabilityUDPPair ||
			issued.Ticket == "" || issued.ExpiresInSeconds <= 0 || issued.ExpiresInSeconds > 900 ||
			protocol.ValidateRelayControlURL(issued.RelayURL) != nil {
			return RelaySession{}, errors.New("managed relay admission is not peer-bound")
		}

		return issued, nil
	}
	var initial RelaySession
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		var err error

		initial, err = fetch(ctx)
		if err == nil {
			break
		}
		if waitBackoff(ctx, backoff) != nil {
			return nil
		}

		backoff = min(backoff*2, 30*time.Second)
	}

	cfg := RelayBridgeConfig{
		RelayURL:                 r.cfg.RelayURL,
		RelayTransport:           protocol.CapabilityUDPPair,
		RelayHTTPClient:          r.cfg.HTTPClient,
		Ticket:                   initial.Ticket,
		TicketLifetime:           time.Duration(initial.ExpiresInSeconds) * time.Second,
		SessionID:                peer.SessionID,
		DeviceID:                 r.cfg.DeviceID,
		DestinationDeviceID:      peer.DeviceID,
		ListenAddress:            "127.0.0.1:0",
		WireGuardAddress:         r.cfg.WireGuardAddress,
		RejectUnconfirmedSources: true,
	}
	bridge, err := newUDPPairBridge(cfg)
	if err != nil {
		return err
	}

	first := initial.Ticket
	provider := func(ctx context.Context) (string, error) {
		if first != "" {
			ticket := first
			first = ""

			return ticket, nil
		}

		fresh, err := fetch(ctx)

		return fresh.Ticket, err
	}
	attempted := false
	defer func() {
		if attempted {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result = errors.Join(result, r.cfg.Endpoints.ClearPeerEndpoint(cleanup, peer.PublicKey))
		}
	}()

	return runUDPPairOwner(ctx, cfg, bridge, provider, func(runCtx context.Context) error {
		attempted = true
		local := bridge.LocalAddr()
		if err := r.cfg.Endpoints.SetPeerEndpoint(
			runCtx,
			peer.PublicKey,
			local.AddrPort(),
		); err != nil {
			return err
		}

		return bridge.Run(runCtx)
	})
}
