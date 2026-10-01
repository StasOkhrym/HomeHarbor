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

// DeviceReader resolves only the target of an explicitly authorized peer update.
type DeviceReader interface {
	Device(context.Context, string) (devices.Device, error)
}
type SnapshotProvider interface {
	Latest(context.Context) (snapshot.Envelope, error)
}
type Handler struct {
	Auth           Authenticator
	Snapshots      SnapshotProvider
	History        SnapshotHistoryProvider
	AllowedOrigins []string
	AuthorizePeer  func(context.Context, devices.Device, devices.Device) bool
	devices        DeviceReader
	hub            *hub
	sessions       *sessionOwner
}

// BroadcastSnapshot sends a committed signed head to currently connected
// nodes. It is intentionally best-effort: the durable snapshot store remains
// the source of truth, and disconnected nodes fetch the same head on retry.
func (h *Handler) BroadcastSnapshot(ctx context.Context, envelope snapshot.Envelope) {
	if h == nil {
		return
	}

	broadcastContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	message, err := snapshotMessage(envelope)
	if err != nil {
		return
	}

	h.hub.broadcastMessage(broadcastContext, "", message)
}

// NewHandler creates the coordination endpoint. Peer authorization is an
// explicit option because candidate exchange is security-sensitive; without
// it the handler refuses candidate updates instead of guessing a mesh policy.
func NewHandler(
	auth Authenticator,
	reader DeviceReader,
	snapshots SnapshotProvider,
	allowedOrigins []string,
	authorizePeer func(context.Context, devices.Device, devices.Device) bool,
) *Handler {
	return &Handler{
		Auth:           auth,
		devices:        reader,
		Snapshots:      snapshots,
		AllowedOrigins: append([]string(nil), allowedOrigins...),
		AuthorizePeer:  authorizePeer,
		hub:            newHub(),
		sessions:       newSessionOwner(),
	}
}

// NewHandlerWithHistory explicitly supplies the signed history dependency used
// by ServeHistory, alongside the latest snapshot used by the WebSocket endpoint.
func NewHandlerWithHistory(
	auth Authenticator,
	reader DeviceReader,
	snapshots SnapshotHistoryProvider,
	allowedOrigins []string,
	authorizePeer func(context.Context, devices.Device, devices.Device) bool,
) *Handler {
	handler := NewHandler(auth, reader, snapshots, allowedOrigins, authorizePeer)
	handler.History = snapshots

	return handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, finish, admitted := h.sessions.begin(r.Context())
	if !admitted {
		http.Error(w, "coordination stopped", http.StatusServiceUnavailable)
		return
	}
	defer finish()
	r = r.WithContext(ctx)
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
	if !h.sessions.track(connection) {
		return
	}
	defer h.sessions.untrack(connection)
	connection.SetReadLimit(64 << 10)
	// Bound the initial read so an authenticated client cannot retain a
	// coordination slot forever without completing protocol negotiation.
	helloContext, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	var hello controlprotocol.Hello
	if err = wsjson.Read(helloContext, connection, &hello); err != nil {
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
		_ = writeJSONWithTimeout(r.Context(), connection, protocolErr)
		_ = connection.Close(websocket.StatusPolicyViolation, protocolErr.Code)
		return
	}
	peer := &peer{id: device.ID, connection: connection, negotiated: negotiated}
	// One live connection per device makes candidate ownership unambiguous and
	// prevents an old connection from continuing to publish endpoint changes.
	if err = h.hub.add(peer); err != nil {
		_ = connection.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	defer h.hub.remove(peer.id)
	if err = writeJSONWithTimeout(
		r.Context(),
		connection,
		map[string]any{"type": "welcome", "protocol": negotiated},
	); err != nil {
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
	message, err := snapshotMessage(signedSnapshot)
	if err != nil {
		_ = connection.Close(websocket.StatusMessageTooBig, "snapshot exceeds envelope limit")
		return
	}
	if err = peer.write(r.Context(), message); err != nil {
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
			if !negotiated.Has(controlprotocol.CapabilityDirectUDP) {
				// A relay-only peer must not publish endpoint candidates. Keeping
				// this check at the authenticated protocol boundary prevents an
				// older client from probing the direct-path feature by sending an
				// otherwise well-formed message.
				_ = connection.Close(
					websocket.StatusPolicyViolation,
					"direct UDP capability was not negotiated",
				)
				return
			}
			var update controlprotocol.CandidateUpdate
			if err := json.Unmarshal(
				message.Payload,
				&update,
			); err != nil ||
				update.Validate() != nil {
				_ = connection.Close(
					websocket.StatusInvalidFramePayloadData,
					"targeted candidate update required",
				)
				return
			}
			if h.devices == nil {
				continue
			}
			destination, destinationErr := h.devices.Device(r.Context(), update.DestinationDeviceID)
			if destinationErr != nil || h.AuthorizePeer == nil ||
				!h.AuthorizePeer(r.Context(), device, destination) {
				continue
			}
			// The sender identity comes from the authenticated WebSocket, never
			// from the candidate payload. The receiver uses it to bind the
			// endpoint update to the peer whose key it is reconciling.
			update.SourceDeviceID = device.ID
			payload, marshalErr := json.Marshal(update)
			if marshalErr != nil {
				continue
			}
			h.hub.sendCandidate(
				r.Context(),
				destination.ID,
				controlprotocol.Message{Type: "candidate.update", Payload: payload},
			)
		case "heartbeat":
			_ = writePayload(
				r.Context(),
				connection,
				"heartbeat.ack",
				map[string]any{"at": time.Now().UTC()},
			)
		}
	}
}

func writePayload(
	ctx context.Context,
	connection *websocket.Conn,
	messageType string,
	value any,
) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return writeJSONWithTimeout(
		ctx,
		connection,
		controlprotocol.Message{Type: messageType, Payload: payload},
	)
}

func writeJSONWithTimeout(ctx context.Context, connection *websocket.Conn, value any) error {
	writeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return wsjson.Write(writeContext, connection, value)
}

type peer struct {
	id         string
	connection *websocket.Conn
	negotiated controlprotocol.Negotiated
	mu         sync.Mutex
}

func (p *peer) write(ctx context.Context, message controlprotocol.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return writeJSONWithTimeout(ctx, p.connection, message)
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

func (h *hub) sendCandidate(
	ctx context.Context,
	destination string,
	message controlprotocol.Message,
) {
	h.mu.RLock()
	peer := h.peers[destination]
	h.mu.RUnlock()
	if peer != nil && peer.negotiated.Has(controlprotocol.CapabilityDirectUDP) {
		_ = peer.write(ctx, message)
	}
}

func (h *hub) broadcastMessage(
	ctx context.Context,
	source string,
	message controlprotocol.Message,
) {
	h.mu.RLock()
	peers := make([]*peer, 0, len(h.peers))
	for id, peer := range h.peers {
		if id != source {
			peers = append(peers, peer)
		}
	}

	h.mu.RUnlock()
	h.broadcastPeers(ctx, peers, message)
}

func (h *hub) broadcastPeers(ctx context.Context, peers []*peer, message controlprotocol.Message) {
	for _, peer := range peers {
		_ = peer.write(ctx, message)
	}
}

type duplicatePeerError struct{}

func (*duplicatePeerError) Error() string { return "device already connected" }
