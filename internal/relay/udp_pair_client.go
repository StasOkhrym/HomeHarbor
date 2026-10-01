package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// UDPPairBridgeConfig describes one local endpoint of the UDP pair relay. The
// bridge forwards bytes between the local WireGuard UDP socket and the relay;
// neither this adapter nor the relay interprets the WireGuard payload.
type UDPPairBridgeConfig struct {
	Ticket           string
	RelayAddress     *net.UDPAddr
	ListenAddress    *net.UDPAddr
	WireGuardAddress *net.UDPAddr
	// OnObservedEndpoint receives the relay's view of this bridge's source
	// address. It is intentionally a callback rather than a field exposed to
	// the relay: node coordination owns candidate publication and can decide
	// whether this endpoint is safe to advertise to a peer.
	OnObservedEndpoint func(netip.AddrPort)
}

// UDPPairBridge owns its local UDP socket and can be restarted independently
// after a relay outage. Every outbound datagram carries the peer-bound ticket,
// while inbound datagrams are accepted only from the configured relay address.
type UDPPairBridge struct {
	cfg             UDPPairBridgeConfig
	udp             *net.UDPConn
	observedMu      sync.RWMutex
	observed        netip.AddrPort
	observedChanges chan struct{}
}

// NewUDPPairBridge creates a local UDP adapter for one relay session.
func NewUDPPairBridge(cfg UDPPairBridgeConfig) (*UDPPairBridge, error) {
	if cfg.Ticket == "" || cfg.RelayAddress == nil || cfg.ListenAddress == nil ||
		cfg.WireGuardAddress == nil {
		return nil, errors.New("UDP pair ticket and addresses are required")
	}
	udp, err := net.ListenUDP("udp", cfg.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen UDP pair bridge: %w", err)
	}
	return &UDPPairBridge{cfg: cfg, udp: udp, observedChanges: make(chan struct{})}, nil
}

// LocalAddr returns the local adapter endpoint to configure as the WireGuard
// peer endpoint. The caller must not close or reuse the underlying socket.
func (b *UDPPairBridge) LocalAddr() net.UDPAddr {
	if b == nil || b.udp == nil {
		return net.UDPAddr{}
	}
	return *cloneUDPAddr(b.udp.LocalAddr().(*net.UDPAddr))
}

// ObservedEndpoint returns the most recent source address reported by the
// relay. A caller must treat it as a candidate, not proof that a direct path
// works; the WireGuard handshake remains the final path validation step.
func (b *UDPPairBridge) ObservedEndpoint() (netip.AddrPort, bool) {
	if b == nil {
		return netip.AddrPort{}, false
	}
	b.observedMu.RLock()
	defer b.observedMu.RUnlock()
	return b.observed, b.observed.IsValid()
}

// ObservedEndpointChanges is notified whenever the relay reports a new source
// address. The channel is replaced after each notification, so consumers can
// wait without polling while preserving the latest value in ObservedEndpoint.
func (b *UDPPairBridge) ObservedEndpointChanges() <-chan struct{} {
	if b == nil {
		return nil
	}
	b.observedMu.RLock()
	defer b.observedMu.RUnlock()
	return b.observedChanges
}

func (b *UDPPairBridge) setObservedEndpoint(endpoint netip.AddrPort) {
	if b == nil || !endpoint.IsValid() {
		return
	}
	b.observedMu.Lock()
	if endpoint == b.observed {
		b.observedMu.Unlock()
		return
	}
	b.observed = endpoint
	previous := b.observedChanges
	b.observedChanges = make(chan struct{})
	callback := b.cfg.OnObservedEndpoint
	b.observedMu.Unlock()
	close(previous)
	if callback != nil {
		callback(endpoint)
	}
}

// Run forwards encrypted datagrams until cancellation or a socket/relay error.
func (b *UDPPairBridge) Run(ctx context.Context) error {
	if b == nil || b.udp == nil {
		return errors.New("UDP pair bridge is not initialized")
	}
	defer func() { _ = b.udp.Close() }()
	// A single goroutine owns reads from this socket. Two concurrent readers
	// cannot safely distinguish local WireGuard packets from relay responses;
	// dispatching by the authenticated relay address avoids silently dropping
	// either direction under load.
	buffer := make([]byte, maxUDPPairDatagramSize)
	for {
		if err := b.udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, source, err := b.udp.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) ||
				ctx.Err() != nil {
				return nil
			}
			return err
		}
		if sameUDPAddr(source, b.cfg.RelayAddress) {
			datagram, decodeErr := DecodeUDPPairDatagram(buffer[:n])
			if decodeErr != nil || datagram.Ticket != "" {
				return errors.New("invalid UDP pair relay datagram")
			}
			switch datagram.Kind {
			case UDPPairKindBinding:
				endpoint, parseErr := netip.ParseAddrPort(string(datagram.Payload))
				if parseErr != nil || !endpoint.IsValid() {
					return errors.New("invalid UDP pair binding datagram")
				}
				b.setObservedEndpoint(endpoint)
				continue
			case UDPPairKindData:
				// Data is already authenticated by the local WireGuard peer after
				// this bridge delivers it; the relay has only selected the peer
				// address and copied the encrypted bytes.
				if _, writeErr := b.udp.WriteToUDP(
					datagram.Payload,
					b.cfg.WireGuardAddress,
				); writeErr != nil {
					return writeErr
				}
				continue
			default:
				return errors.New("invalid UDP pair relay datagram kind")
			}
		}
		if !sameUDPAddr(source, b.cfg.WireGuardAddress) {
			// A datagram from a third-party endpoint is a candidate direct
			// WireGuard packet. The kernel WireGuard peer remains the authority
			// for cryptographic authentication; the bridge only delivers bytes
			// to that local socket and never treats them as plaintext.
			if _, writeErr := b.udp.WriteToUDP(
				buffer[:n],
				b.cfg.WireGuardAddress,
			); writeErr != nil {
				return writeErr
			}
			continue
		}
		data, encodeErr := EncodeUDPPairDatagram(b.cfg.Ticket, buffer[:n])
		if encodeErr != nil {
			return encodeErr
		}
		if _, writeErr := b.udp.WriteToUDP(data, b.cfg.RelayAddress); writeErr != nil {
			return writeErr
		}
	}
}

func sameUDPAddr(left, right *net.UDPAddr) bool {
	if left == nil || right == nil {
		return false
	}
	return left.Port == right.Port && (right.IP.IsUnspecified() || left.IP.Equal(right.IP))
}
