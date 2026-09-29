package relay

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type WebSocketHandler struct {
	Hub            *Hub
	Tickets        TicketIssuer
	AllowedOrigins []string
	MaxPacketBytes int64
}

func (h WebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, err := h.Tickets.Verify(relayTicketFromRequest(r))
	if err != nil {
		http.Error(w, "invalid relay ticket", http.StatusUnauthorized)
		return
	}
	options := &websocket.AcceptOptions{}
	if len(h.AllowedOrigins) > 0 {
		options.OriginPatterns = h.AllowedOrigins
	}
	connection, err := websocket.Accept(w, r, options)
	if err != nil {
		return
	}
	defer func() { _ = connection.CloseNow() }()
	maxPacketBytes := h.MaxPacketBytes
	if maxPacketBytes <= 0 {
		maxPacketBytes = maxPacketPayload + 512
	}
	connection.SetReadLimit(maxPacketBytes)
	sender := &webSocketSender{connection: connection}
	if err = h.Hub.Register(claims.SessionID, claims.DeviceID, sender); err != nil {
		_ = connection.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	defer h.Hub.Unregister(claims.SessionID, claims.DeviceID)
	for {
		readContext, readCancel := context.WithTimeout(r.Context(), 2*time.Minute)
		messageType, data, readErr := connection.Read(readContext)
		readCancel()
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

func relayTicketFromRequest(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(value) <= len("Bearer ") || !strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(value[len("Bearer "):])
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
	writeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.connection.Write(writeContext, websocket.MessageBinary, data)
}
