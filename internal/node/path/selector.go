package path

import (
	"sync"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type PathSelector struct {
	mu      sync.RWMutex
	current protocol.Path
	changed chan struct{}
}

func NewPathSelector() *PathSelector {
	return &PathSelector{current: protocol.PathRelay, changed: make(chan struct{})}
}

func (s *PathSelector) Current() protocol.Path { s.mu.RLock(); defer s.mu.RUnlock(); return s.current }

// Changes returns a channel that is closed whenever the selected path changes.
// Callers must fetch a fresh channel after receiving a notification; closing
// instead of sending makes a path transition observable to every watcher
// without blocking a transport goroutine.
func (s *PathSelector) Changes() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.changed
}

func (s *PathSelector) DirectHandshakeSucceeded() { s.set(protocol.PathDirect) }

func (s *PathSelector) DirectFailed() { s.set(protocol.PathRelay) }

func (s *PathSelector) set(path protocol.Path) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.current == path {
		return
	}

	s.current = path
	close(s.changed)
	s.changed = make(chan struct{})
}
