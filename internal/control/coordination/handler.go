package coordination

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	controlprotocol "github.com/sokhrym/go-tunnels/internal/protocol"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type Authenticator interface {
	Authenticate(context.Context, string) (devices.Device, error)
}
type SnapshotProvider interface {
	Latest(context.Context) (snapshot.Envelope, error)
}
type Handler struct {
	Auth           Authenticator
	Snapshots      SnapshotProvider
	AllowedOrigins []string
	hub            *hub
}

func NewHandler(auth Authenticator, snapshots SnapshotProvider, allowedOrigins []string) *Handler {
	return &Handler{Auth: auth, Snapshots: snapshots, AllowedOrigins: append([]string(nil), allowedOrigins...), hub: newHub()}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	credential := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	device, err := h.Auth.Authenticate(r.Context(), credential)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	options := &websocket.AcceptOptions{OriginPatterns: h.AllowedOrigins}
	connection, err := websocket.Accept(w, r, options)
	if err != nil {
		return
	}
	defer func() { _ = connection.CloseNow() }()
	connection.SetReadLimit(64 << 10)
	// Bound the initial read so an authenticated client cannot retain a
	// coordination slot forever without completing protocol negotiation.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	var hello controlprotocol.Hello
	if err = wsjson.Read(ctx, connection, &hello); err != nil {
		cancel()
		_ = connection.Close(websocket.StatusPolicyViolation, "hello required")
		return
	}
	cancel()
	if hello.DeviceID != device.ID {
		_ = connection.Close(websocket.StatusPolicyViolation, "device mismatch")
		return
	}
	negotiated, protocolErr := controlprotocol.Negotiate(hello)
	if protocolErr != nil {
		_ = wsjson.Write(r.Context(), connection, protocolErr)
		_ = connection.Close(websocket.StatusPolicyViolation, protocolErr.Code)
		return
	}
	peer := &peer{id: device.ID, connection: connection}
	// One live connection per device makes candidate ownership unambiguous and
	// prevents an old connection from continuing to publish endpoint changes.
	if err = h.hub.add(peer); err != nil {
		_ = connection.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	defer h.hub.remove(peer.id)
	if err = wsjson.Write(r.Context(), connection, map[string]any{"type": "welcome", "protocol": negotiated}); err != nil {
		return
	}
	if h.Snapshots == nil {
		_ = connection.Close(websocket.StatusTryAgainLater, "signed snapshot unavailable")
		return
	}
	signedSnapshot, err := h.Snapshots.Latest(r.Context())
	if err != nil {
		_ = connection.Close(websocket.StatusTryAgainLater, "signed snapshot unavailable")
		return
	}
	if err = writePayload(r.Context(), connection, "network.snapshot", signedSnapshot); err != nil {
		return
	}
	for {
		var message controlprotocol.Message
		readContext, readCancel := context.WithTimeout(r.Context(), 2*time.Minute)
		err = wsjson.Read(readContext, connection, &message)
		readCancel()
		if err != nil {
			return
		}
		switch message.Type {
		case "candidate.update":
			h.hub.broadcast(r.Context(), peer.id, message)
		case "heartbeat":
			_ = writePayload(r.Context(), connection, "heartbeat.ack", map[string]any{"at": time.Now().UTC()})
		}
	}
}

func writePayload(ctx context.Context, connection *websocket.Conn, messageType string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return wsjson.Write(ctx, connection, controlprotocol.Message{Type: messageType, Payload: payload})
}

type peer struct {
	id         string
	connection *websocket.Conn
	mu         sync.Mutex
}

func (p *peer) write(ctx context.Context, message controlprotocol.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return wsjson.Write(ctx, p.connection, message)
}

type hub struct {
	mu    sync.RWMutex
	peers map[string]*peer
}

func newHub() *hub { return &hub{peers: make(map[string]*peer)} }
func (h *hub) add(peer *peer) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.peers[peer.id]; exists {
		return &duplicatePeerError{}
	}

	h.peers[peer.id] = peer

	return nil
}
func (h *hub) remove(id string) { h.mu.Lock(); delete(h.peers, id); h.mu.Unlock() }
func (h *hub) broadcast(ctx context.Context, source string, message controlprotocol.Message) {
	h.mu.RLock()
	// Snapshot peers under the lock, then release it before network I/O. A slow
	// client must not block registrations or disconnects for every other peer.
	peers := make([]*peer, 0, len(h.peers))
	for id, peer := range h.peers {
		if id != source {
			peers = append(peers, peer)
		}
	}
	h.mu.RUnlock()
	for _, peer := range peers {
		_ = peer.write(ctx, message)
	}
}

type duplicatePeerError struct{}

func (*duplicatePeerError) Error() string { return "device already connected" }
