package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sokhrym/go-tunnels/internal/node"
	platformconfig "github.com/sokhrym/go-tunnels/internal/platform/config"
	controlprotocol "github.com/sokhrym/go-tunnels/internal/protocol"
)

func main() {
	configPath := flag.String("config", "", "TOML client configuration path")
	statePath := flag.String("state", "state/client.json", "node state file")
	controlURL := flag.String("control", "", "control plane URL")
	token := flag.String("token", "", "one-time enrollment token")
	refresh := flag.Bool("refresh", false, "rotate the existing device credential")
	name := flag.String("name", "linux-client", "device name")
	relayURL := flag.String("relay", "", "relay WebSocket URL; starts the relay-only bridge when set")
	relayUDPAddress := flag.String("relay-udp", "", "relay udp_pair_v1 host:port; preferred when set")
	relayTicket := flag.String("relay-ticket", "", "short-lived relay ticket; omit to request one from control")
	sessionID := flag.String("relay-session", "", "relay session ID")
	destination := flag.String("relay-destination", "", "destination device ID")
	bridgeListen := flag.String("bridge-listen", "127.0.0.1:51822", "local UDP endpoint used by the WireGuard peer")
	wireGuardAddress := flag.String("wireguard-address", "127.0.0.1:51820", "local WireGuard UDP listen address")
	interfaceName := flag.String("wg-interface", "", "Linux WireGuard interface; blank keeps bridge-only mode")
	listenPort := flag.Uint("wg-port", 51820, "WireGuard UDP listen port")
	peerPublicKey := flag.String("wg-peer-key", "", "destination WireGuard public key")
	overlayAddress := flag.String("wg-overlay", "", "overlay CIDR assigned to this interface")
	allowedPrefixes := flag.String("wg-allowed-prefixes", "", "comma-separated peer allowed IP prefixes")
	routes := flag.String("wg-routes", "", "comma-separated Linux routes installed through the interface")
	coordinationURL := flag.String("coordination", "", "control coordination WebSocket URL")
	rootPublicKeyFile := flag.String("root-public-key", "", "trusted companion root public key file")
	networkID := flag.String("network-id", "home", "network ID used for signed snapshot verification")
	directCandidates := flag.String("direct-candidates", "", "comma-separated direct UDP candidates for the relay peer")
	stunServer := flag.String("stun", "", "optional UDP STUN URI used to discover the bridge socket's public candidate")
	flag.Parse()
	var err error
	if *configPath != "" {
		cfg, configErr := platformconfig.LoadClient(*configPath)
		if configErr != nil {
			err = configErr
		} else {
			if !flagProvided("state") {
				*statePath = cfg.Identity.StatePath
			}
			if !flagProvided("control") {
				*controlURL = cfg.Identity.ControlURL
			}
			if !flagProvided("token") {
				*token = cfg.Identity.Token
			}
			if !flagProvided("refresh") {
				*refresh = cfg.Identity.Refresh
			}
			if !flagProvided("name") {
				*name = cfg.Identity.Name
			}
			if !flagProvided("relay") {
				*relayURL = cfg.Relay.WebSocketURL
			}
			if !flagProvided("relay-udp") {
				*relayUDPAddress = cfg.Relay.UDPAddress
			}
			if !flagProvided("relay-ticket") {
				*relayTicket = cfg.Relay.Ticket
			}
			if !flagProvided("relay-session") {
				*sessionID = cfg.Relay.SessionID
			}
			if !flagProvided("relay-destination") {
				*destination = cfg.Relay.DestinationDevice
			}
			if !flagProvided("bridge-listen") {
				*bridgeListen = cfg.Relay.ListenAddress
			}
			if !flagProvided("wireguard-address") {
				*wireGuardAddress = cfg.Relay.WireGuardAddress
			}
			if !flagProvided("stun") {
				*stunServer = cfg.Relay.STUNServer
			}
			if !flagProvided("wg-interface") {
				*interfaceName = cfg.WireGuard.InterfaceName
			}
			if !flagProvided("wg-port") {
				*listenPort = cfg.WireGuard.ListenPort
			}
			if !flagProvided("wg-peer-key") {
				*peerPublicKey = cfg.WireGuard.PeerPublicKey
			}
			if !flagProvided("wg-overlay") {
				*overlayAddress = cfg.WireGuard.OverlayAddress
			}
			if !flagProvided("wg-allowed-prefixes") {
				*allowedPrefixes = cfg.WireGuard.AllowedPrefixes
			}
			if !flagProvided("wg-routes") {
				*routes = cfg.WireGuard.Routes
			}
			if !flagProvided("coordination") {
				*coordinationURL = cfg.Coordination.URL
			}
			if !flagProvided("root-public-key") {
				*rootPublicKeyFile = cfg.Coordination.RootPublicKeyFile
			}
			if !flagProvided("network-id") {
				*networkID = cfg.Coordination.NetworkID
			}
			if !flagProvided("direct-candidates") {
				*directCandidates = cfg.Direct.Candidates
			}
		}
	}
	state, stateErr := node.LoadOrCreate(*statePath)
	if err == nil {
		err = stateErr
	}
	if err == nil && *controlURL != "" && *token != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = node.Enroll(ctx, nil, *controlURL, *token, *name, &state)
	} else if err == nil && *controlURL != "" && *refresh {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = node.RefreshCredential(ctx, nil, *controlURL, &state)
	}
	if err == nil {
		err = state.Save(*statePath)
	}
	var snapshotWireGuard *node.SnapshotWireGuardReconciler
	var clientReconciler *node.ClientReconciler
	var pathSelector *controlprotocol.PathSelector
	var candidateHandler func(context.Context, controlprotocol.CandidateUpdate) error
	var candidateProvider func(context.Context) ([]controlprotocol.CandidateUpdate, error)
	var candidateSet *node.CandidateSet
	if err == nil && *coordinationURL != "" {
		if *interfaceName == "" || *rootPublicKeyFile == "" {
			err = fmt.Errorf("-wg-interface and -root-public-key are required for client coordination")
		} else {
			snapshotWireGuard, err = node.NewSnapshotWireGuardReconciler(*interfaceName, state.DeviceID, state.WireGuard.PrivateKey, uint16(*listenPort))
			if err == nil {
				clientReconciler = node.NewClientReconciler(*interfaceName, state.DeviceID)
				pathSelector = controlprotocol.NewPathSelector()
			}
		}
	}
	if err == nil && *coordinationURL != "" && *interfaceName != "" && *peerPublicKey != "" && *destination != "" {
		candidates, candidateErr := node.ParseDirectCandidates(*directCandidates)
		if candidateErr != nil {
			err = candidateErr
		} else {
			prober, proberErr := node.NewWireGuardHandshakeProber(*interfaceName)
			if proberErr != nil {
				err = proberErr
			} else {
				manager, managerErr := node.NewCandidatePathManager(state.DeviceID, *destination, *peerPublicKey, snapshotWireGuard, pathSelector, prober)
				if managerErr != nil {
					err = managerErr
				} else {
					candidateHandler = manager.HandleCandidateUpdate
					candidateSet = node.NewCandidateSet(candidates)
					candidateProvider = func(context.Context) ([]controlprotocol.CandidateUpdate, error) {
						current := candidateSet.Snapshot()
						if len(current) == 0 {
							return nil, nil
						}
						return []controlprotocol.CandidateUpdate{{DestinationDeviceID: *destination, Candidates: current}}, nil
					}
				}
			}
		}
	}
	if err == nil && (*relayURL != "" || *relayUDPAddress != "" || *relayTicket != "") {
		if *relayURL == "" && *relayUDPAddress == "" && *relayTicket != "" {
			err = fmt.Errorf("-relay or -relay-udp is required when -relay-ticket is supplied")
		} else if *sessionID == "" || *destination == "" {
			err = fmt.Errorf("-relay-session and -relay-destination are required for relay mode")
		} else if *relayTicket == "" {
			var session node.RelaySession
			session, err = node.IssueRelaySession(context.Background(), nil, *controlURL, state.DeviceCredential, *sessionID, *destination)
			if err == nil {
				*relayURL, *relayUDPAddress, *relayTicket = session.RelayURL, session.RelayUDPAddress, session.Ticket
			}
		}
	}
	var components []func(context.Context) error
	if err == nil && (*relayURL != "" || *relayUDPAddress != "") {
		var ticketProvider node.RelayTicketProvider
		if *controlURL != "" {
			ticketProvider = func(providerContext context.Context) (string, error) {
				session, providerErr := node.IssueRelaySession(providerContext, nil, *controlURL, state.DeviceCredential, *sessionID, *destination)
				if providerErr != nil {
					return "", providerErr
				}
				return session.Ticket, nil
			}
		}
		if *interfaceName == "" {
			components = append(components, func(componentContext context.Context) error {
				return node.RunRelayBridgeLoop(componentContext, node.RelayBridgeConfig{RelayURL: *relayURL, RelayUDPAddress: *relayUDPAddress, Ticket: *relayTicket, SessionID: *sessionID, DeviceID: state.DeviceID, DestinationDeviceID: *destination, ListenAddress: *bridgeListen, WireGuardAddress: *wireGuardAddress, STUNServer: *stunServer, OnObservedEndpoint: func(endpoint netip.AddrPort) {
					if candidateSet != nil {
						candidateSet.SetObservedEndpoint(endpoint)
					}
				}}, ticketProvider)
			})
		} else {
			allowed, parseErr := node.ParsePrefixList(*allowedPrefixes)
			if parseErr != nil {
				err = parseErr
			} else {
				var routePrefixes []netip.Prefix
				routePrefixes, parseErr = node.ParsePrefixList(*routes)
				if parseErr == nil {
					components = append(components, func(componentContext context.Context) error {
						return node.RunKernelRelayLoop(componentContext, node.KernelRelayConfig{RelayBridgeConfig: node.RelayBridgeConfig{RelayURL: *relayURL, RelayUDPAddress: *relayUDPAddress, Ticket: *relayTicket, SessionID: *sessionID, DeviceID: state.DeviceID, DestinationDeviceID: *destination, ListenAddress: *bridgeListen, WireGuardAddress: *wireGuardAddress, STUNServer: *stunServer, OnObservedEndpoint: func(endpoint netip.AddrPort) {
							if candidateSet != nil {
								candidateSet.SetObservedEndpoint(endpoint)
							}
						}}, InterfaceName: *interfaceName, PrivateKey: state.WireGuard.PrivateKey, ListenPort: uint16(*listenPort), OverlayAddress: *overlayAddress, PeerPublicKey: *peerPublicKey, AllowedPrefixes: allowed, Routes: routePrefixes, EndpointUpdater: snapshotWireGuard, PathSelector: pathSelector}, ticketProvider)
					})
				} else {
					err = parseErr
				}
			}
		}
	}
	if err == nil && *coordinationURL != "" {
		rootPublicKey, keyErr := node.LoadPublicKeyFile(*rootPublicKeyFile)
		if keyErr != nil {
			err = keyErr
		} else {
			components = append(components, func(componentContext context.Context) error {
				var candidateChanges <-chan struct{}
				if candidateSet != nil {
					candidateChanges = candidateSet.Changes()
				}
				return node.RunCoordinationLoop(componentContext, node.CoordinationConfig{URL: *coordinationURL, Credential: state.DeviceCredential, DeviceID: state.DeviceID, NetworkID: *networkID, RootPublicKey: rootPublicKey, CandidateHandler: candidateHandler, CandidateProvider: candidateProvider, CandidateChanges: candidateChanges}, node.NewCompositeSnapshotApplier(clientReconciler, snapshotWireGuard))
			})
		}
	}
	if err == nil && len(components) > 0 {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		err = node.RunComponents(ctx, components...)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("client enrolled: %s\n", state.DeviceID)
}

func flagProvided(name string) bool {
	provided := false
	flag.Visit(func(item *flag.Flag) {
		if item.Name == name {
			provided = true
		}
	})
	return provided
}
