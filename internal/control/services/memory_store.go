package services

import (
	"context"
	"slices"
	"strings"
	"sync"
)

// MemoryStore is an in-process test double for Repository.
type MemoryStore struct {
	mu       sync.Mutex
	services map[string]Service
	profiles map[string]AccessProfile
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		services: make(map[string]Service),
		profiles: make(map[string]AccessProfile),
	}
}

func (s *MemoryStore) CreateService(_ context.Context, item Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.services[item.ID]; exists {
		return ErrDuplicateID
	}
	s.services[item.ID] = item
	return nil
}

func (s *MemoryStore) ListServices(_ context.Context) ([]Service, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Service, 0, len(s.services))
	for _, item := range s.services {
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b Service) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func (s *MemoryStore) ListServicesForDevice(_ context.Context, deviceID string) ([]Service, error) {
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
	out := make([]Service, 0, len(serviceIDs))
	for serviceID := range serviceIDs {
		if item, ok := s.services[serviceID]; ok {
			out = append(out, item)
		}
	}
	slices.SortFunc(out, func(a, b Service) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func (s *MemoryStore) CreateProfile(_ context.Context, profile AccessProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.profiles[profile.ID]; exists {
		return ErrDuplicateID
	}
	s.profiles[profile.ID] = profile
	return nil
}

func (s *MemoryStore) ListProfiles(_ context.Context) ([]AccessProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AccessProfile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		out = append(out, profile)
	}
	slices.SortFunc(out, func(a, b AccessProfile) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

var _ Repository = (*MemoryStore)(nil)
