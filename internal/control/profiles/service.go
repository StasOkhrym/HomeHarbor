// Package profiles owns access profiles and validates explicit memberships.
package profiles

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/services"
)

var (
	ErrDuplicateID      = errors.New("access profile ID already exists")
	ErrServiceNotFound  = errors.New("service not found")
	ErrDeviceNotAllowed = errors.New("device is not allowed in access profile")
)

type AccessProfile struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	DeviceIDs  []string  `json:"device_ids"`
	ServiceIDs []string  `json:"service_ids"`
	CreatedAt  time.Time `json:"created_at"`
}

type Repository interface {
	CreateProfile(context.Context, AccessProfile) error
	ListProfiles(context.Context) ([]AccessProfile, error)
}

type ServiceReader interface {
	List(context.Context) ([]services.Service, error)
}
type DeviceActiveChecker func(context.Context, string) (bool, error)

type Service struct {
	store        Repository
	services     ServiceReader
	now          func() time.Time
	deviceActive DeviceActiveChecker
}

func NewService(
	store Repository,
	serviceReader ServiceReader,
	now func() time.Time,
	deviceActive DeviceActiveChecker,
) *Service {
	if now == nil {
		now = time.Now
	}

	return &Service{store: store, services: serviceReader, now: now, deviceActive: deviceActive}
}

func (s *Service) Create(ctx context.Context, profile AccessProfile) (AccessProfile, error) {
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.ID == "" || profile.Name == "" {
		return AccessProfile{}, errors.New("profile ID and name are required")
	}

	profile.DeviceIDs = uniqueSorted(profile.DeviceIDs)
	profile.ServiceIDs = uniqueSorted(profile.ServiceIDs)
	if len(profile.ServiceIDs) == 0 {
		return AccessProfile{}, errors.New("profile must contain at least one service")
	}
	if s.services == nil {
		return AccessProfile{}, errors.New("service validation is not configured")
	}

	knownServices, err := s.services.List(ctx)
	if err != nil {
		return AccessProfile{}, err
	}

	known := make(map[string]struct{}, len(knownServices))
	for _, item := range knownServices {
		known[item.ID] = struct{}{}
	}

	for _, id := range profile.ServiceIDs {
		if _, ok := known[id]; !ok {
			return AccessProfile{}, fmt.Errorf("%w: %s", ErrServiceNotFound, id)
		}
	}

	if len(profile.DeviceIDs) > 0 && s.deviceActive == nil {
		return AccessProfile{}, errors.New("device validation is not configured")
	}

	for _, id := range profile.DeviceIDs {
		active, checkErr := s.deviceActive(ctx, id)
		if checkErr != nil {
			return AccessProfile{}, checkErr
		}
		if !active {
			return AccessProfile{}, fmt.Errorf("%w: %s", ErrDeviceNotAllowed, id)
		}
	}

	profile.CreatedAt = s.now().UTC()

	if err = s.store.CreateProfile(ctx, profile); err != nil {
		return AccessProfile{}, err
	}

	return profile, nil
}

func (s *Service) List(ctx context.Context) ([]AccessProfile, error) {
	return s.store.ListProfiles(ctx)
}

func uniqueSorted(values []string) []string {
	values = slices.Clone(values)
	slices.Sort(values)
	return slices.Compact(values)
}
