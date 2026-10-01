package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	UDPPairProtocolVersion    uint8 = 1
	udpPairHeaderSize               = 4 + 1 + 1 + 2
	udpPairMagic                    = "GTUP"
	maxUDPPairDatagramSize          = 65507 // Maximum IPv4 UDP payload.
	defaultUDPPairMaxSessions       = 4096
	defaultUDPPairIdleTimeout       = 2 * time.Minute
)

const (
	UDPPairKindData    uint8 = 1
	UDPPairKindBinding uint8 = 2
)

// UDPPairDatagram is the wire envelope for the raw relay ingress. Client
// datagrams carry a short-lived ticket; relay-to-client datagrams deliberately
// carry no ticket because the destination address was selected from a
// previously authenticated, peer-bound session.
type UDPPairDatagram struct {
	Kind    uint8
	Ticket  string
	Payload []byte
}

// EncodeUDPPairDatagram encodes a client-to-relay datagram. The ticket is
// required so an arbitrary UDP sender cannot allocate a session slot or cause
// opaque bytes to be forwarded to another device.
func EncodeUDPPairDatagram(ticket string, payload []byte) ([]byte, error) {
	if ticket == "" {
		return nil, errors.New("UDP pair ticket is required")
	}
	return encodeUDPPairDatagram(UDPPairKindData, ticket, payload)
}

func encodeUDPPairDatagram(kind uint8, ticket string, payload []byte) ([]byte, error) {
	if (kind != UDPPairKindData && kind != UDPPairKindBinding) || len(ticket) > maxTicketLength || len(payload) == 0 ||
		len(payload) > maxPacketPayload ||
		udpPairHeaderSize+len(ticket)+len(payload) > maxUDPPairDatagramSize {
		return nil, errors.New("invalid UDP pair datagram size")
	}
	if len(ticket) > int(^uint16(0)) {
		return nil, errors.New("UDP pair ticket is too long")
	}
	data := make([]byte, udpPairHeaderSize+len(ticket)+len(payload))
	copy(data, udpPairMagic)
	data[4] = UDPPairProtocolVersion
	data[5] = kind
	binary.BigEndian.PutUint16(data[6:8], uint16(len(ticket)))
	copy(data[udpPairHeaderSize:], ticket)
	copy(data[udpPairHeaderSize+len(ticket):], payload)
	return data, nil
}

// DecodeUDPPairDatagram bounds every length before slicing. It accepts an
// empty ticket only for server-forwarded frames; the relay's ingress path
// rejects such frames before session lookup.
func DecodeUDPPairDatagram(data []byte) (UDPPairDatagram, error) {
	if len(data) < udpPairHeaderSize || string(data[:4]) != udpPairMagic || data[4] != UDPPairProtocolVersion {
		return UDPPairDatagram{}, errors.New("invalid UDP pair header")
	}
	kind := data[5]
	if kind != UDPPairKindData && kind != UDPPairKindBinding {
		return UDPPairDatagram{}, errors.New("invalid UDP pair kind")
	}
	ticketLength := int(binary.BigEndian.Uint16(data[6:8]))
	if ticketLength > maxTicketLength || udpPairHeaderSize+ticketLength >= len(data) {
		return UDPPairDatagram{}, errors.New("invalid UDP pair ticket length")
	}
	payload := data[udpPairHeaderSize+ticketLength:]
	if len(payload) == 0 || len(payload) > maxPacketPayload {
		return UDPPairDatagram{}, errors.New("invalid UDP pair payload size")
	}
	return UDPPairDatagram{
		Kind:    kind,
		Ticket:  string(data[udpPairHeaderSize : udpPairHeaderSize+ticketLength]),
		Payload: append([]byte(nil), payload...),
	}, nil
}

type udpPairPeer struct {
	address     *net.UDPAddr
	destination string
	lastSeen    time.Time
}

// UDPPairRelay forwards opaque WireGuard datagrams between exactly two
// authenticated, mutually bound endpoints. It owns only the UDP socket and
// session metadata; it never parses or decrypts the payload.
type UDPPairRelay struct {
	connection  *net.UDPConn
	tickets     TicketIssuer
	mu          sync.Mutex
	sessions    map[string]map[string]*udpPairPeer
	maxSessions int
	idleTimeout time.Duration
}

// NewUDPPairRelay creates a relay on an already-bound UDP socket. Keeping the
// socket ownership explicit lets the app layer expose one stable ingress while
// tests and future per-session listeners can provide their own socket.
func NewUDPPairRelay(connection *net.UDPConn, tickets TicketIssuer) *UDPPairRelay {
	return &UDPPairRelay{
		connection:  connection,
		tickets:     tickets,
		sessions:    make(map[string]map[string]*udpPairPeer),
		maxSessions: defaultUDPPairMaxSessions,
		idleTimeout: defaultUDPPairIdleTimeout,
	}
}

// Run serves authenticated UDP pair datagrams until cancellation or socket
// failure. Malformed/untrusted datagrams are dropped locally; one hostile UDP
// packet must not terminate every unrelated tunnel session.
func (r *UDPPairRelay) Run(ctx context.Context) error {
	if r == nil || r.connection == nil {
		return errors.New("UDP pair relay is not initialized")
	}
	buffer := make([]byte, maxUDPPairDatagramSize)
	for {
		if err := r.connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, source, err := r.connection.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		target, payload, processErr := r.processDatagram(buffer[:n], source, time.Now())
		if processErr != nil {
			continue
		}
		binding, encodeErr := encodeUDPPairDatagram(UDPPairKindBinding, "", []byte(source.String()))
		if encodeErr != nil {
			continue
		}
		if _, err := r.connection.WriteToUDP(binding, source); err != nil && ctx.Err() != nil {
			return nil
		}
		if target == nil {
			continue
		}
		forwarded, encodeErr := encodeUDPPairDatagram(UDPPairKindData, "", payload)
		if encodeErr != nil {
			continue
		}
		if _, err := r.connection.WriteToUDP(forwarded, target); err != nil && ctx.Err() != nil {
			return nil
		}
	}
}

func (r *UDPPairRelay) processDatagram(data []byte, source *net.UDPAddr, now time.Time) (*net.UDPAddr, []byte, error) {
	datagram, err := DecodeUDPPairDatagram(data)
	if err != nil || datagram.Ticket == "" {
		return nil, nil, errors.New("invalid authenticated UDP pair datagram")
	}
	claims, err := r.tickets.Verify(datagram.Ticket)
	if err != nil || claims.DestinationDeviceID == "" {
		return nil, nil, errors.New("unbound UDP pair ticket")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	peers := r.sessions[claims.SessionID]
	if peers == nil {
		if len(r.sessions) >= r.maxSessions {
			return nil, nil, errors.New("UDP pair session limit reached")
		}
		peers = make(map[string]*udpPairPeer, 2)
		r.sessions[claims.SessionID] = peers
	}
	peer, exists := peers[claims.DeviceID]
	if exists {
		if peer.destination != claims.DestinationDeviceID {
			return nil, nil, errors.New("UDP pair destination changed")
		}
		peer.address = cloneUDPAddr(source)
		peer.lastSeen = now
	} else {
		if len(peers) >= 2 {
			return nil, nil, errors.New("UDP pair already has two endpoints")
		}
		for deviceID, other := range peers {
			if other.destination != claims.DeviceID || claims.DestinationDeviceID != deviceID {
				return nil, nil, errors.New("UDP pair peers are not mutually bound")
			}
		}
		peers[claims.DeviceID] = &udpPairPeer{
			address:     cloneUDPAddr(source),
			destination: claims.DestinationDeviceID,
			lastSeen:    now,
		}
	}
	targetPeer := peers[claims.DestinationDeviceID]
	if targetPeer == nil || targetPeer.destination != claims.DeviceID {
		return nil, nil, nil
	}
	return cloneUDPAddr(targetPeer.address), datagram.Payload, nil
}

func (r *UDPPairRelay) pruneLocked(now time.Time) {
	for sessionID, peers := range r.sessions {
		for deviceID, peer := range peers {
			if now.Sub(peer.lastSeen) > r.idleTimeout {
				delete(peers, deviceID)
			}
		}
		if len(peers) == 0 {
			delete(r.sessions, sessionID)
		}
	}
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	clone := *address
	clone.IP = append(net.IP(nil), address.IP...)
	return &clone
}
