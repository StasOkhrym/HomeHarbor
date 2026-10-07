package routes

import (
	"context"
	"slices"
	"strings"
	"sync"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/routes"
)

// Repository is an in-process test double for Repository.
type Repository struct {
	mu    sync.Mutex
	items map[string]domainpkg.Advertisement
}

func NewRepository() *Repository { return &Repository{items: make(map[string]domainpkg.Advertisement)} }

func (s *Repository) Save(ctx context.Context, item domainpkg.Advertisement) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[item.ID] = item
	return nil
}

func (s *Repository) SetStatus(ctx context.Context, id string, status domainpkg.Status) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[id]
	if !ok {
		return domainpkg.ErrAdvertisementNotFound
	}

	item.Status = status
	s.items[id] = item

	return nil
}

func (s *Repository) List(
	ctx context.Context,
	status *domainpkg.Status,
) ([]domainpkg.Advertisement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	out := []domainpkg.Advertisement{}
	for _, item := range s.items {
		if status == nil || item.Status == *status {
			out = append(out, item)
		}
	}

	slices.SortFunc(out, func(a, b domainpkg.Advertisement) int {
		if n := a.CreatedAt.Compare(b.CreatedAt); n != 0 {
			return n
		}

		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

var _ domainpkg.Repository = (*Repository)(nil)
