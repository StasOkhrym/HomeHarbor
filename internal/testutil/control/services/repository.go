package services

import (
	"context"
	"slices"
	"strings"
	"sync"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/services"
)

// Repository is an in-process test double for Repository.
type Repository struct {
	mu         sync.Mutex
	services   map[string]domainpkg.Service
	membership func(string) []string
}

func NewRepository() *Repository {
	return &Repository{
		services: make(map[string]domainpkg.Service),
	}
}

func (s *Repository) CreateService(ctx context.Context, item domainpkg.Service) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.services[item.ID]; exists {
		return domainpkg.ErrDuplicateID
	}

	s.services[item.ID] = item

	return nil
}

func (s *Repository) ListServices(ctx context.Context) ([]domainpkg.Service, error) {
	if err := ctx.Err(); err != nil {
		var zero []domainpkg.Service
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]domainpkg.Service, 0, len(s.services))
	for _, item := range s.services {
		out = append(out, item)
	}

	slices.SortFunc(out, func(a, b domainpkg.Service) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func (s *Repository) ListServicesForDevice(
	ctx context.Context,
	deviceID string,
) ([]domainpkg.Service, error) {
	if err := ctx.Err(); err != nil {
		var zero []domainpkg.Service
		return zero, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	serviceIDs := make(map[string]struct{})
	if s.membership != nil {
		for _, id := range s.membership(deviceID) {
			serviceIDs[id] = struct{}{}
		}
	}

	out := make([]domainpkg.Service, 0, len(serviceIDs))
	for serviceID := range serviceIDs {
		if item, ok := s.services[serviceID]; ok {
			out = append(out, item)
		}
	}

	slices.SortFunc(out, func(a, b domainpkg.Service) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// SetMemberships wires the profile test adapter to service visibility.
func (s *Repository) SetMemberships(membership func(string) []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.membership = membership
}

var _ domainpkg.Repository = (*Repository)(nil)
