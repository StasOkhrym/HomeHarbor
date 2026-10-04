package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/agent/dns"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

// NewRuntime assembles either node role without opening a tunnel. Run owns the
// deny bootstrap and supervised workers; invalid trust configuration is rejected
// before identity creation, enrollment or any privileged network operation.
func NewRuntime(_ context.Context, role Role, cfg config.Node) (*App, error) {
	if cfg.Runtime == (config.Runtime{}) {
		cfg.Runtime = config.DefaultRuntime(false)
	}

	if err := validateRuntime(role, cfg); err != nil {
		return nil, err
	}

	return &App{startup: func(ctx context.Context) (*App, error) {
		return startRuntime(ctx, role, cfg)
	}}, nil
}

// startRuntime owns enrollment and local state writes. It assembles workers
// without starting them; the returned App still installs the deny guard first.
func startRuntime(ctx context.Context, role Role, cfg config.Node) (*App, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	kernel := cfg.WireGuard.InterfaceName != "" || cfg.Coordination.URL != ""
	var root ed25519.PublicKey
	var err error
	if kernel {
		root, err = node.LoadPublicKeyFile(cfg.Coordination.RootPublicKeyFile)
		if err != nil {
			return nil, err
		}
	}
	store, err := localstate.Open(cfg.Identity.StatePath)
	if err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = store.Close()
		}
	}()
	state, err := prepareIdentity(ctx, cfg, store)
	if err != nil {
		return nil, err
	}
	var peers *node.SnapshotWireGuardReconciler
	var paths *protocol.PathSelector
	if kernel {
		peers, err = node.NewSnapshotWireGuardReconciler(
			cfg.WireGuard.InterfaceName,
			state.DeviceID,
			state.WireGuard.PrivateKey,
			uint16(cfg.WireGuard.ListenPort),
		)
		if err != nil {
			return nil, err
		}
		paths = protocol.NewPathSelector()
	}
	candidates, err := prepareCandidates(cfg, state, peers, paths)
	if err != nil {
		return nil, err
	}
	var workers []lifecycle.Worker
	if cfg.Relay.WebSocketURL != "" || cfg.Relay.UDPAddress != "" || cfg.Relay.Ticket != "" {
		relay, err := prepareRelay(ctx, cfg, state, peers, paths, candidates.set)
		if err != nil {
			return nil, err
		}
		workers = append(workers, lifecycle.Worker{Name: "relay", Component: relay})
	}
	var bootstrap lifecycle.Component
	if kernel {
		coordination, guard, err := prepareCoordination(role, cfg, state, root, peers, candidates)
		if err != nil {
			return nil, err
		}
		bootstrap = guard
		workers = append(workers, lifecycle.Worker{Name: "coordination", Component: coordination})
	}
	handedOff = true
	return &App{bootstrap: bootstrap, workers: workers, close: store.Close}, nil
}

func prepareIdentity(
	ctx context.Context,
	cfg config.Node,
	store *localstate.Store,
) (node.State, error) {
	state, err := node.LoadOrCreateFrom(store)
	if err != nil {
		return node.State{}, err
	}
	operation, cancel := context.WithTimeout(ctx, cfg.Runtime.OperationTimeout)
	defer cancel()
	if cfg.Identity.ControlURL != "" && cfg.Identity.Token != "" && state.DeviceCredential == "" {
		err = node.Enroll(
			operation,
			nil,
			cfg.Identity.ControlURL,
			cfg.Identity.Token,
			cfg.Identity.Name,
			&state,
		)
	} else if cfg.Identity.ControlURL != "" && cfg.Identity.Refresh {
		err = node.RefreshCredential(operation, nil, cfg.Identity.ControlURL, &state)
	}
	if err != nil {
		return node.State{}, err
	}
	if err := state.SaveTo(store); err != nil {
		return node.State{}, err
	}
	return state, nil
}

type candidateBindings struct {
	set     *node.CandidateSet
	handle  func(context.Context, protocol.CandidateUpdate) error
	provide func(context.Context) ([]protocol.CandidateUpdate, error)
}

func prepareCandidates(
	cfg config.Node,
	state node.State,
	peers *node.SnapshotWireGuardReconciler,
	paths *protocol.PathSelector,
) (candidateBindings, error) {
	if peers == nil || cfg.WireGuard.PeerPublicKey == "" || cfg.Relay.DestinationDevice == "" {
		return candidateBindings{}, nil
	}
	endpoints, err := node.ParseDirectCandidates(cfg.Direct.Candidates)
	if err != nil {
		return candidateBindings{}, err
	}
	prober, err := node.NewWireGuardHandshakeProber(cfg.WireGuard.InterfaceName)
	if err != nil {
		return candidateBindings{}, err
	}
	manager, err := node.NewCandidatePathManager(
		state.DeviceID,
		cfg.Relay.DestinationDevice,
		cfg.WireGuard.PeerPublicKey,
		peers,
		paths,
		prober,
	)
	if err != nil {
		return candidateBindings{}, err
	}
	set := node.NewCandidateSet(endpoints)
	return candidateBindings{
		set:    set,
		handle: manager.HandleCandidateUpdate,
		provide: func(context.Context) ([]protocol.CandidateUpdate, error) {
			current := set.Snapshot()
			if len(current) == 0 {
				return nil, nil
			}
			return []protocol.CandidateUpdate{
				{DestinationDeviceID: cfg.Relay.DestinationDevice, Candidates: current},
			}, nil
		},
	}, nil
}

func prepareRelay(
	ctx context.Context,
	cfg config.Node,
	state node.State,
	peers *node.SnapshotWireGuardReconciler,
	paths *protocol.PathSelector,
	candidates *node.CandidateSet,
) (lifecycle.Component, error) {
	if cfg.Relay.SessionID == "" || cfg.Relay.DestinationDevice == "" {
		return nil, errors.New("-relay-session and -relay-destination are required for relay mode")
	}
	if cfg.Relay.WebSocketURL == "" && cfg.Relay.UDPAddress == "" && cfg.Relay.Ticket != "" {
		return nil, errors.New("-relay or -relay-udp is required when -relay-ticket is supplied")
	}
	bridge := node.RelayBridgeConfig{
		RelayURL:            cfg.Relay.WebSocketURL,
		RelayUDPAddress:     cfg.Relay.UDPAddress,
		Ticket:              cfg.Relay.Ticket,
		SessionID:           cfg.Relay.SessionID,
		DeviceID:            state.DeviceID,
		DestinationDeviceID: cfg.Relay.DestinationDevice,
		ListenAddress:       cfg.Relay.ListenAddress,
		WireGuardAddress:    cfg.Relay.WireGuardAddress,
		STUNServer:          cfg.Relay.STUNServer,
	}
	bridge.OnObservedEndpoint = func(endpoint netip.AddrPort) {
		if candidates != nil {
			candidates.SetObservedEndpoint(endpoint)
		}
	}
	var renew node.RelayTicketProvider
	if cfg.Identity.ControlURL != "" {
		renew = func(ctx context.Context) (string, error) {
			session, err := node.IssueRelaySession(
				ctx,
				nil,
				cfg.Identity.ControlURL,
				state.DeviceCredential,
				cfg.Relay.SessionID,
				cfg.Relay.DestinationDevice,
			)
			return session.Ticket, err
		}
	}
	if bridge.Ticket == "" {
		operation, cancel := context.WithTimeout(ctx, cfg.Runtime.OperationTimeout)
		defer cancel()
		session, err := node.IssueRelaySession(
			operation,
			nil,
			cfg.Identity.ControlURL,
			state.DeviceCredential,
			cfg.Relay.SessionID,
			cfg.Relay.DestinationDevice,
		)
		if err != nil {
			return nil, err
		}
		bridge.RelayURL, bridge.RelayUDPAddress, bridge.Ticket = session.RelayURL, session.RelayUDPAddress, session.Ticket
		bridge.TicketLifetime = time.Duration(session.ExpiresInSeconds) * time.Second
	}
	if cfg.WireGuard.InterfaceName == "" {
		return lifecycle.Func(
			func(ctx context.Context) error { return node.RunRelayBridgeLoop(ctx, bridge, renew) },
		), nil
	}
	allowed, err := node.ParsePrefixList(cfg.WireGuard.AllowedPrefixes)
	if err != nil {
		return nil, err
	}
	routes, err := node.ParsePrefixList(cfg.WireGuard.Routes)
	if err != nil {
		return nil, err
	}
	tunnel := node.KernelRelayConfig{
		RelayBridgeConfig: bridge,
		InterfaceName:     cfg.WireGuard.InterfaceName,
		PrivateKey:        state.WireGuard.PrivateKey,
		ListenPort:        uint16(cfg.WireGuard.ListenPort),
		OverlayAddress:    cfg.WireGuard.OverlayAddress,
		PeerPublicKey:     cfg.WireGuard.PeerPublicKey,
		AllowedPrefixes:   allowed,
		Routes:            routes,
		EndpointUpdater:   peers,
		PathSelector:      paths,
	}
	return lifecycle.Func(
		func(ctx context.Context) error { return node.RunKernelRelayLoop(ctx, tunnel, renew) },
	), nil
}

func prepareCoordination(
	role Role,
	cfg config.Node,
	state node.State,
	root ed25519.PublicKey,
	peers *node.SnapshotWireGuardReconciler,
	candidates candidateBindings,
) (lifecycle.Component, lifecycle.Component, error) {
	connection := node.CoordinationConfig{
		URL:               cfg.Coordination.URL,
		Credential:        state.DeviceCredential,
		DeviceID:          state.DeviceID,
		NetworkID:         cfg.Coordination.NetworkID,
		RootPublicKey:     root,
		StatePath:         cfg.Identity.StatePath + ".snapshot",
		CandidateHandler:  candidates.handle,
		CandidateProvider: candidates.provide,
	}
	if candidates.set != nil {
		connection.CandidateChanges = candidates.set.Changes()
	}
	if role == Client {
		applier := node.NewCompositeSnapshotApplier(
			nil,
			node.NewClientReconciler(cfg.WireGuard.InterfaceName, state.DeviceID),
			peers,
		)
		return lifecycle.Func(
			func(ctx context.Context) error { return node.RunCoordinationLoop(ctx, connection, applier) },
		), nil, nil
	}
	var managedDNS *dns.Manager
	var resolver *node.DNSReconciler
	if cfg.DNS.Link != "" {
		var err error
		managedDNS, err = dns.NewManager(cfg.DNS.Link)
		if err != nil {
			return nil, nil, err
		}
		resolver = node.NewDNSReconciler(managedDNS)
	}
	gateway := node.NewGatewayReconcilerWithOptions(
		cfg.WireGuard.InterfaceName,
		state.DeviceID,
		resolver,
		cfg.DNS.EnableForwarding,
	)
	applier := node.NewCompositeSnapshotApplier(gateway, peers)
	worker := lifecycle.Func(func(ctx context.Context) error {
		err := node.RunCoordinationLoop(ctx, connection, applier)
		if managedDNS == nil {
			return err
		}
		// DNS belongs to the process lifetime, not the cancelled worker context.
		cleanup, cancel := context.WithTimeout(context.Background(), cfg.Runtime.CleanupTimeout)
		defer cancel()
		return errors.Join(err, managedDNS.Close(cleanup))
	})
	return worker, lifecycle.Func(gateway.Bootstrap), nil
}

// RunCommand is shared by the thin entrypoints; it never exits the process.
func RunCommand(ctx context.Context, role Role, cfg config.Node) error {
	app, err := NewRuntime(ctx, role, cfg)
	if err != nil {
		return fmt.Errorf("configure node: %w", err)
	}

	return app.Run(ctx)
}
