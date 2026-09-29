package relay

import (
	"context"
	"net/http"
	"sync"

	"github.com/coder/websocket"
)

type WebSocketHandler struct {
	Hub     *Hub
	Tickets TicketIssuer
}

func (h WebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, err := h.Tickets.Verify(r.URL.Query().Get("ticket"))
	if err != nil {
		http.Error(w, "invalid relay ticket", http.StatusUnauthorized)
		return
	}
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	sender := &webSocketSender{connection: connection}
	if err = h.Hub.Register(claims.SessionID, claims.DeviceID, sender); err != nil {
		_ = connection.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	defer h.Hub.Unregister(claims.SessionID, claims.DeviceID)
	for {
		messageType, data, readErr := connection.Read(r.Context())
		if readErr != nil {
			return
		}
		if messageType != websocket.MessageBinary {
			_ = connection.Close(websocket.StatusUnsupportedData, "binary packets required")
			return
		}
		packet, decodeErr := DecodePacket(data)
		if decodeErr != nil {
			_ = connection.Close(websocket.StatusInvalidFramePayloadData, decodeErr.Error())
			return
		}
		if forwardErr := h.Hub.Forward(r.Context(), claims.SessionID, claims.DeviceID, packet); forwardErr != nil {
			continue
		}
	}
}

type webSocketSender struct {
	mu         sync.Mutex
	connection *websocket.Conn
}

func (s *webSocketSender) Send(ctx context.Context, packet Packet) error {
	data, err := EncodePacket(packet)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connection.Write(ctx, websocket.MessageBinary, data)
}
