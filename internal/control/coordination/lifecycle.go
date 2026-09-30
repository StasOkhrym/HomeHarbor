package coordination

import (
	"context"
	"errors"
	"sync"

	"github.com/coder/websocket"
)

// Run owns upgraded sockets and joins every admitted handler on cancellation.
// HTTP Shutdown does not close hijacked connections, so the app supervises this
// component alongside its HTTP server and closes stores only after both exit.
func (h *Handler) Run(ctx context.Context) error {
	s := h.sessions
	s.mu.Lock()
	if s.running || s.closed {
		s.mu.Unlock()
		return errors.New("coordination runtime already started or closed")
	}

	s.running = true
	s.mu.Unlock()
	<-ctx.Done()
	s.mu.Lock()
	s.closed = true
	s.cancel()
	connections := make([]*websocket.Conn, 0, len(s.connections))
	for c := range s.connections {
		connections = append(connections, c)
	}

	s.mu.Unlock()
	for _, c := range connections {
		_ = c.CloseNow()
	}

	s.handlers.Wait()
	return nil
}

type sessionOwner struct {
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	running, closed bool
	handlers        sync.WaitGroup
	connections     map[*websocket.Conn]struct{}
}

func newSessionOwner() *sessionOwner {
	ctx, cancel := context.WithCancel(context.Background())
	return &sessionOwner{ctx: ctx, cancel: cancel, connections: make(map[*websocket.Conn]struct{})}
}

func (s *sessionOwner) begin(request context.Context) (context.Context, func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, nil, false
	}

	// Add and the transition to closed share a lock: no handler can be added
	// once shutdown starts waiting. Count authentication/hello too, not just
	// registered peers, because those stages already use application stores.
	s.handlers.Add(1)
	ctx, cancel := context.WithCancel(request)
	stop := context.AfterFunc(s.ctx, cancel)

	return ctx, func() { stop(); cancel(); s.handlers.Done() }, true
}

func (s *sessionOwner) track(c *websocket.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return false
	}

	s.connections[c] = struct{}{}

	return true
}

func (s *sessionOwner) untrack(c *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.connections, c)
}
