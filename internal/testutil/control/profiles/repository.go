package profiles

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
	memoryservices "github.com/StasOkhrym/homeharbor/internal/testutil/control/services"
)

// Repository holds profile test data and grants service visibility in tests.
type Repository struct {
	mu       sync.Mutex
	profiles map[string]profiles.AccessProfile
}

func NewRepository(services *memoryservices.Repository) *Repository {
	r := &Repository{profiles: make(map[string]profiles.AccessProfile)}
	if services != nil {
		services.SetMemberships(r.ServiceIDsForDevice)
	}

	return r
}

func (r *Repository) CreateProfile(ctx context.Context, profile profiles.AccessProfile) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.profiles[profile.ID]; ok {
		return profiles.ErrDuplicateID
	}

	r.profiles[profile.ID] = clone(profile)

	return nil
}

func (r *Repository) ListProfiles(ctx context.Context) ([]profiles.AccessProfile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]profiles.AccessProfile, 0, len(r.profiles))
	for _, item := range r.profiles {
		out = append(out, clone(item))
	}

	slices.SortFunc(out, func(a, b profiles.AccessProfile) int {
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

func (r *Repository) ServiceIDsForDevice(deviceID string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := []string{}
	for _, profile := range r.profiles {
		if slices.Contains(profile.DeviceIDs, deviceID) {
			out = append(out, profile.ServiceIDs...)
		}
	}

	return out
}

func clone(value profiles.AccessProfile) profiles.AccessProfile {
	value.DeviceIDs = slices.Clone(value.DeviceIDs)
	value.ServiceIDs = slices.Clone(value.ServiceIDs)

	return value
}

var _ profiles.Repository = (*Repository)(nil)
