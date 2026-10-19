package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type UDPPairBridgeConfig struct {
	ControlURL          string
	Ticket              string
	SessionID           string
	DeviceID            string
	DestinationDeviceID string
	ListenAddress       *net.UDPAddr
	WireGuardAddress    *net.UDPAddr
	// HTTPClient may provide a trusted private CA. Certificate verification
	// remains mandatory; nil uses the normal system trust store.
	HTTPClient         *http.Client
	BindTimeout        time.Duration
	MaxDatagramBytes   int
	OnObservedEndpoint func(netip.AddrPort)
	// Relay-only owners reject sources outside the bound relay and local WG
	// socket. False preserves the legacy encrypted direct-candidate path.
	RejectUnconfirmedSources bool
}

type binding struct {
	address   *net.UDPAddr
	challenge chan string
}

// UDPPairBridge retains a local WireGuard socket and a separate routable egress
// across admissions and rebindings. Each socket has one owned reader, so renewal
// cannot steal packets. A loopback source cannot reach a remote relay on Linux.
type UDPPairBridge struct {
	cfg             UDPPairBridgeConfig
	udp             *net.UDPConn
	egress          *net.UDPConn
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	relay           *net.UDPAddr
	pending         *binding
	observed        netip.AddrPort
	observedChanges chan struct{}
	bindMu          sync.Mutex
	wg              sync.WaitGroup
	err             chan error
	connected       chan struct{}
	connectedOnce   sync.Once
	closeOnce       sync.Once
	started         bool
}

func NewUDPPairBridge(cfg UDPPairBridgeConfig) (*UDPPairBridge, error) {
	if err := protocol.ValidateRelayControlURL(cfg.ControlURL); err != nil {
		return nil, err
	}

	if cfg.Ticket == "" || cfg.SessionID == "" || cfg.DeviceID == "" ||
		cfg.DestinationDeviceID == "" ||
		cfg.DeviceID == cfg.DestinationDeviceID ||
		cfg.ListenAddress == nil ||
		cfg.WireGuardAddress == nil {
		return nil, errors.New("UDP pair ticket, peer identities and UDP addresses required")
	}

	if cfg.BindTimeout == 0 {
		cfg.BindTimeout = 10 * time.Second
	}

	if cfg.MaxDatagramBytes == 0 {
		cfg.MaxDatagramBytes = 65507
	}

	if cfg.BindTimeout < 0 || cfg.MaxDatagramBytes < 1 || cfg.MaxDatagramBytes > 65507 {
		return nil, errors.New("invalid UDP pair bridge limits")
	}

	client := http.Client{}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}

	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	httpTransport, ok := transport.(*http.Transport)
	//nolint:staticcheck // Reject the deprecated TLS hook too: it can bypass certificate verification.
	if !ok || httpTransport.DialTLS != nil || httpTransport.DialTLSContext != nil {
		return nil, errors.New("UDP pair requires a verifying HTTP TLS transport")
	}

	ownedTransport := httpTransport.Clone()
	if ownedTransport.TLSClientConfig == nil {
		ownedTransport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		ownedTransport.TLSClientConfig = ownedTransport.TLSClientConfig.Clone()
	}

	if ownedTransport.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("UDP pair TLS verification cannot be disabled")
	}

	client.Transport = ownedTransport
	// net/http otherwise forwards Authorization on a same-host downgrade.
	// A relay control endpoint is exact and never follows redirects.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTPClient = &client
	cfg.ListenAddress = cloneUDPAddr(cfg.ListenAddress)
	cfg.WireGuardAddress = cloneUDPAddr(cfg.WireGuardAddress)

	udp, err := net.ListenUDP("udp", cfg.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen UDP pair bridge: %w", err)
	}

	egress, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("listen UDP pair egress: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	b := &UDPPairBridge{
		cfg:             cfg,
		udp:             udp,
		egress:          egress,
		ctx:             ctx,
		cancel:          cancel,
		err:             make(chan error, 2), // At most one terminal error per reader.
		connected:       make(chan struct{}),
		observedChanges: make(chan struct{}),
	}

	return b, nil
}

func (b *UDPPairBridge) LocalAddr() net.UDPAddr {
	return *cloneUDPAddr(b.udp.LocalAddr().(*net.UDPAddr))
}
func (b *UDPPairBridge) Connected() <-chan struct{} { return b.connected }

func (b *UDPPairBridge) ObservedEndpoint() (netip.AddrPort, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.observed, b.observed.IsValid()
}

func (b *UDPPairBridge) ObservedEndpointChanges() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.observedChanges
}

func (b *UDPPairBridge) Close() error {
	b.closeOnce.Do(func() {
		b.cancel()
		_ = b.udp.Close()
		_ = b.egress.Close()
		// Bind is synchronous but may be running in a renewal owner. Its
		// context is cancelled above before awaiting it and the UDP reader.
		b.bindMu.Lock()
		defer b.bindMu.Unlock()

		b.wg.Wait()
		b.cfg.HTTPClient.CloseIdleConnections()
	})
	return nil
}

func (b *UDPPairBridge) Run(ctx context.Context) error {
	defer func() { _ = b.Close() }()

	b.mu.Lock()
	bound := b.relay != nil
	b.mu.Unlock()
	if !bound {
		if err := b.Bind(ctx, b.cfg.Ticket); err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}
	}

	select {
	case <-ctx.Done():
		return nil
	case <-b.ctx.Done():
		return nil
	case err := <-b.err:
		return err
	}
}

// Bind performs a fresh control authentication on the same local UDP socket.
// A failed renewal leaves the existing route usable; callers can retry when
// control returns. Established sessions do not need renewal at ticket expiry.
func (b *UDPPairBridge) Bind(parent context.Context, ticket string) error {
	b.bindMu.Lock()
	defer b.bindMu.Unlock()

	if b.ctx.Err() != nil {
		return net.ErrClosed
	}

	if !b.started {
		b.started = true
		b.wg.Add(2)
		go b.readUDP(b.udp, true)
		go b.readUDP(b.egress, false)
	}

	ctx, cancel := context.WithTimeout(parent, b.cfg.BindTimeout)
	defer cancel()

	stop := context.AfterFunc(b.ctx, cancel)
	defer stop()

	headers := http.Header{"Authorization": {"Bearer " + ticket}}
	c, _, err := websocket.Dial(
		ctx,
		b.cfg.ControlURL,
		&websocket.DialOptions{
			HTTPClient:      b.cfg.HTTPClient,
			HTTPHeader:      headers,
			CompressionMode: websocket.CompressionDisabled,
		},
	)
	if err != nil {
		return fmt.Errorf("UDP pair control: %w", err)
	}
	defer func() { _ = c.CloseNow() }()

	c.SetReadLimit(2048)
	var offer UDPPairMessage

	if err := wsjson.Read(ctx, c, &offer); err != nil {
		return err
	}

	if offer.Protocol != UDPPairProtocol || offer.Kind != "offer" ||
		offer.SessionID != b.cfg.SessionID ||
		offer.DeviceID != b.cfg.DeviceID ||
		offer.DestinationDeviceID != b.cfg.DestinationDeviceID ||
		len(offer.Nonce) != 43 {
		return errors.New("UDP pair offer identity or version mismatch")
	}

	address, err := net.ResolveUDPAddr("udp", offer.UDPAddress)
	if err != nil || address.Port == 0 || address.IP.IsUnspecified() {
		return errors.New("invalid UDP pair ingress address")
	}

	binding := &binding{address: address, challenge: make(chan string, 1)}
	b.mu.Lock()
	b.pending = binding
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.pending = nil; b.mu.Unlock() }()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	probe := func() error { _, err := b.egress.WriteToUDP([]byte("HHUP"+offer.Nonce), address); return err }
	if err := probe(); err != nil {
		return err
	}

	var challenge string
wait:
	for {
		select {
		case challenge = <-binding.challenge:
			break wait
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := probe(); err != nil {
				return err
			}
		}
	}

	if err := wsjson.Write(
		ctx,
		c,
		UDPPairMessage{Protocol: UDPPairProtocol, Kind: "confirm", Challenge: challenge},
	); err != nil {
		return err
	}

	var bound UDPPairMessage

	if err := wsjson.Read(ctx, c, &bound); err != nil {
		return err
	}

	observed, err := netip.ParseAddrPort(bound.ObservedEndpoint)
	if err != nil || bound.Protocol != UDPPairProtocol || bound.Kind != "bound" {
		return errors.New("invalid UDP pair confirmation")
	}

	// Renewal proves reachability on the retained ingress, so the confirmed
	// endpoint mapping is also valid for data behind endpoint-dependent NAT.
	boundAddress, err := net.ResolveUDPAddr("udp", bound.UDPAddress)
	if err != nil || boundAddress.Port == 0 || boundAddress.IP.IsUnspecified() {
		return errors.New("invalid confirmed UDP pair ingress address")
	}

	b.mu.Lock()
	b.relay = cloneUDPAddr(boundAddress)
	if observed != b.observed {
		b.observed = observed
		close(b.observedChanges)
		b.observedChanges = make(chan struct{})
	}

	b.mu.Unlock()
	b.connectedOnce.Do(func() { close(b.connected) })
	if b.cfg.OnObservedEndpoint != nil {
		b.cfg.OnObservedEndpoint(observed)
	}

	return nil
}

func (b *UDPPairBridge) readUDP(socket *net.UDPConn, local bool) {
	defer b.wg.Done()

	buffer := make([]byte, 65535)
	for {
		n, source, err := socket.ReadFromUDP(buffer)
		if err != nil {
			if b.ctx.Err() == nil {
				b.err <- err
			}

			return
		}

		b.mu.Lock()
		relayAddress := cloneUDPAddr(b.relay)
		pending := b.pending
		b.mu.Unlock()
		if !local && pending != nil && sameUDPAddr(source, pending.address) {
			if n == 47 && strings.HasPrefix(string(buffer[:n]), "HHUC") {
				select {
				case pending.challenge <- string(buffer[4:n]):
				default:
				}

				continue
			}
			// During renewal the probe and data ports are identical. Do not
			// discard ordinary WireGuard packets while waiting for control ACK.
		}

		if n == 0 || n > b.cfg.MaxDatagramBytes {
			continue
		}
		if b.cfg.RejectUnconfirmedSources &&
			((local && !sameUDPAddr(source, b.cfg.WireGuardAddress)) ||
				(!local && !sameUDPAddr(source, relayAddress))) {
			continue
		}

		var target *net.UDPAddr
		outbound := b.udp
		// Only the configured local WireGuard socket may send to relay.
		if local && sameUDPAddr(source, b.cfg.WireGuardAddress) {
			target = relayAddress
			outbound = b.egress
		} else {
			target = b.cfg.WireGuardAddress
		}

		// Third-party UDP remains an opaque direct-path candidate; the kernel
		// WireGuard peer authenticates it. It never changes the relay binding.
		if target == nil {
			continue
		}

		if _, err := outbound.WriteToUDP(buffer[:n], target); err != nil {
			b.err <- err
			return
		}
	}
}
