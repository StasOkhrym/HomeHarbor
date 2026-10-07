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
	mu       sync.Mutex
	services map[string]domainpkg.Service
	profiles map[string]domainpkg.AccessProfile
}

func NewRepository() *Repository {
	return &Repository{
		services: make(map[string]domainpkg.Service),
		profiles: make(map[string]domainpkg.AccessProfile),
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
	for _, profile := range s.profiles {
		if slices.Contains(profile.DeviceIDs, deviceID) {
			for _, serviceID := range profile.ServiceIDs {
				serviceIDs[serviceID] = struct{}{}
			}
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

func (s *Repository) CreateProfile(ctx context.Context, profile domainpkg.AccessProfile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.profiles[profile.ID]; exists {
		return domainpkg.ErrDuplicateID
	}
	s.profiles[profile.ID] = cloneProfile(profile)
	return nil
}

func (s *Repository) ListProfiles(ctx context.Context) ([]domainpkg.AccessProfile, error) {
	if err := ctx.Err(); err != nil {
		var zero []domainpkg.AccessProfile
		return zero, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domainpkg.AccessProfile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		out = append(out, cloneProfile(profile))
	}
	slices.SortFunc(
		out,
		func(a, b domainpkg.AccessProfile) int { return strings.Compare(a.ID, b.ID) },
	)
	return out, nil
}

var _ domainpkg.Repository = (*Repository)(nil)

func cloneProfile(profile domainpkg.AccessProfile) domainpkg.AccessProfile {
	profile.DeviceIDs = slices.Clone(profile.DeviceIDs)
	profile.ServiceIDs = slices.Clone(profile.ServiceIDs)
	return profile
}
