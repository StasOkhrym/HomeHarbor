package routes

import (
	"context"
	"sync"
)

// MemoryStore is an in-process test double for Repository.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]Advertisement
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{items: make(map[string]Advertisement)} }
func (s *MemoryStore) Save(_ context.Context, item Advertisement) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[item.ID] = item
	return nil
}

func (s *MemoryStore) SetStatus(_ context.Context, id string, status Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return ErrAdvertisementNotFound
	}
	item.Status = status
	s.items[id] = item
	return nil
}

func (s *MemoryStore) List(_ context.Context, status *Status) ([]Advertisement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Advertisement{}
	for _, item := range s.items {
		if status == nil || item.Status == *status {
			out = append(out, item)
		}
	}
	return out, nil
}

var _ Repository = (*MemoryStore)(nil)
