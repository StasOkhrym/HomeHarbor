package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const defaultBridgePacketLimit = maxPacketPayload + 512

// BridgeConfig describes one side of a relay-only datagram path. The UDP
// listener is the endpoint configured in the local WireGuard peer; packets
// arriving there are opaque WireGuard datagrams and are never decrypted here.
type BridgeConfig struct {
	RelayURL            string
	Ticket              string
	SessionID           string
	DeviceID            string
	DestinationDeviceID string
	ListenAddress       *net.UDPAddr
	WireGuardAddress    *net.UDPAddr
	AllowedOrigins      []string
}

// Bridge forwards encrypted UDP datagrams through one authenticated WebSocket.
// It owns both sockets and the WebSocket connection; Run must be called once
// and cancellation closes all three resources so reconnect logic can replace
// the bridge without leaking goroutines.
type Bridge struct {
	cfg        BridgeConfig
	udp        *net.UDPConn
	writeMu    sync.Mutex
	connected  chan struct{}
	connection *websocket.Conn
}

func NewBridge(cfg BridgeConfig) (*Bridge, error) {
	if cfg.RelayURL == "" || cfg.Ticket == "" || cfg.SessionID == "" || cfg.DeviceID == "" ||
		cfg.DestinationDeviceID == "" {
		return nil, errors.New("relay URL, ticket, session, and device identities are required")
	}
	if cfg.ListenAddress == nil || cfg.WireGuardAddress == nil {
		return nil, errors.New("relay bridge UDP addresses are required")
	}
	udp, err := net.ListenUDP("udp", cfg.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen relay bridge UDP socket: %w", err)
	}
	return &Bridge{cfg: cfg, udp: udp, connected: make(chan struct{})}, nil
}

func (b *Bridge) LocalAddr() net.UDPAddr {
	if b == nil || b.udp == nil {
		return net.UDPAddr{}
	}
	return *b.udp.LocalAddr().(*net.UDPAddr)
}

// Connected closes after the authenticated WebSocket handshake succeeds.
func (b *Bridge) Connected() <-chan struct{} { return b.connected }

func (b *Bridge) Run(ctx context.Context) error {
	if b == nil || b.udp == nil {
		return errors.New("relay bridge is not initialized")
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+b.cfg.Ticket)
	connection, _, err := websocket.Dial(
		ctx,
		b.cfg.RelayURL,
		&websocket.DialOptions{HTTPHeader: header, CompressionMode: websocket.CompressionDisabled},
	)
	if err != nil {
		_ = b.udp.Close()
		return fmt.Errorf("dial relay: %w", err)
	}
	b.connection = connection
	close(b.connected)
	connection.SetReadLimit(defaultBridgePacketLimit)
	defer func() {
		_ = connection.CloseNow()
		_ = b.udp.Close()
	}()

	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	go b.readUDP(bridgeCtx, errCh)
	go b.readWebSocket(bridgeCtx, errCh)
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

func (b *Bridge) readUDP(ctx context.Context, errCh chan<- error) {
	buffer := make([]byte, maxPacketPayload)
	for {
		if err := b.udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			errCh <- err
			return
		}
		n, _, err := b.udp.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				select {
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				default:
					continue
				}
			}
			errCh <- err
			return
		}
		packet := Packet{
			SessionID:           b.cfg.SessionID,
			SourceDeviceID:      b.cfg.DeviceID,
			DestinationDeviceID: b.cfg.DestinationDeviceID,
			Payload:             append([]byte(nil), buffer[:n]...),
		}
		data, err := EncodePacket(packet)
		if err != nil {
			errCh <- err
			return
		}
		b.writeMu.Lock()
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = b.connection.Write(writeCtx, websocket.MessageBinary, data)
		cancel()
		b.writeMu.Unlock()
		if err != nil {
			errCh <- err
			return
		}
	}
}

func (b *Bridge) readWebSocket(ctx context.Context, errCh chan<- error) {
	for {
		messageType, data, err := b.connection.Read(ctx)
		if err != nil {
			errCh <- err
			return
		}
		if messageType != websocket.MessageBinary {
			errCh <- errors.New("relay returned a non-binary message")
			return
		}
		packet, err := DecodePacket(data)
		if err != nil {
			errCh <- err
			return
		}
		if packet.SessionID != b.cfg.SessionID || packet.SourceDeviceID != b.cfg.DestinationDeviceID ||
			packet.DestinationDeviceID != b.cfg.DeviceID {
			errCh <- errors.New("relay packet identity mismatch")
			return
		}
		if _, err = b.udp.WriteToUDP(packet.Payload, b.cfg.WireGuardAddress); err != nil {
			errCh <- err
			return
		}
	}
}
