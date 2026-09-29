package relay

import (
	"context"
	"errors"
	"sync"
)

type Sender interface {
	Send(context.Context, Packet) error
}
type Hub struct {
	mu    sync.RWMutex
	peers map[string]map[string]Sender
}

func NewHub() *Hub { return &Hub{peers: make(map[string]map[string]Sender)} }
func (h *Hub) Register(sessionID, deviceID string, sender Sender) error {
	if sessionID == "" || deviceID == "" || sender == nil {
		return errors.New("session, device, and sender are required")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[sessionID] == nil {
		h.peers[sessionID] = make(map[string]Sender)
	}
	if _, exists := h.peers[sessionID][deviceID]; exists {
		return errors.New("relay peer already connected")
	}
	h.peers[sessionID][deviceID] = sender
	return nil
}

func (h *Hub) Unregister(sessionID, deviceID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if peers := h.peers[sessionID]; peers != nil {
		delete(peers, deviceID)
		if len(peers) == 0 {
			delete(h.peers, sessionID)
		}
	}
}

func (h *Hub) Forward(ctx context.Context, authenticatedSession, authenticatedDevice string, packet Packet) error {
	if packet.SessionID != authenticatedSession || packet.SourceDeviceID != authenticatedDevice {
		return errors.New("relay packet identity mismatch")
	}
	h.mu.RLock()
	sender := h.peers[packet.SessionID][packet.DestinationDeviceID]
	h.mu.RUnlock()
	if sender == nil {
		return errors.New("relay destination unavailable")
	}
	// Never hold the hub lock while writing to a peer. WebSocket backpressure is
	// per connection and must not stall unrelated relay sessions.
	return sender.Send(ctx, packet)
}
