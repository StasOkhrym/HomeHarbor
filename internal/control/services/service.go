// Package services owns the user-facing service catalog and access profiles.
// The policy compiler consumes these concepts later; the catalog itself never
// exposes database tables to HTTP handlers.
package services

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

type Kind string

const (
	KindWeb    Kind = "web"
	KindNative Kind = "native"
)

var (
	ErrServiceNotFound  = errors.New("service not found")
	ErrProfileNotFound  = errors.New("access profile not found")
	ErrDuplicateID      = errors.New("service or profile ID already exists")
	ErrDeviceNotAllowed = errors.New("device is not allowed in access profile")
)

type Service struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        Kind      `json:"kind"`
	URL         string    `json:"url"`
	NativeURL   string    `json:"native_url,omitempty"`
	HealthURL   string    `json:"health_url,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type AccessProfile struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	DeviceIDs  []string  `json:"device_ids"`
	ServiceIDs []string  `json:"service_ids"`
	CreatedAt  time.Time `json:"created_at"`
}

type Store interface {
	CreateService(context.Context, Service) error
	ListServices(context.Context) ([]Service, error)
	CreateProfile(context.Context, AccessProfile) error
	ListProfiles(context.Context) ([]AccessProfile, error)
}

// DeviceActiveChecker is supplied by the composition root so this module can
// validate profile membership without importing the devices repository or
// exposing its tables. A profile may remain empty for an invite template.
type DeviceActiveChecker func(context.Context, string) (bool, error)

type Option func(*Catalog)

func WithDeviceActiveChecker(checker DeviceActiveChecker) Option {
	return func(catalog *Catalog) { catalog.deviceActive = checker }
}

type Catalog struct {
	store        Store
	now          func() time.Time
	deviceActive DeviceActiveChecker
}

func NewService(store Store, now func() time.Time, options ...Option) *Catalog {
	if now == nil {
		now = time.Now
	}
	catalog := &Catalog{store: store, now: now}
	for _, option := range options {
		option(catalog)
	}
	return catalog
}

func (c *Catalog) Create(ctx context.Context, item Service) (Service, error) {
	if err := validateService(item); err != nil {
		return Service{}, err
	}

	item.ID = strings.TrimSpace(item.ID)
	item.Name = strings.TrimSpace(item.Name)
	item.CreatedAt = c.now().UTC()

	if err := c.store.CreateService(ctx, item); err != nil {
		return Service{}, err
	}

	return item, nil
}

func (c *Catalog) List(ctx context.Context) ([]Service, error) { return c.store.ListServices(ctx) }

func (c *Catalog) CreateProfile(ctx context.Context, profile AccessProfile) (AccessProfile, error) {
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
	services, err := c.store.ListServices(ctx)
	if err != nil {
		return AccessProfile{}, err
	}
	known := make(map[string]struct{}, len(services))
	for _, item := range services {
		known[item.ID] = struct{}{}
	}
	for _, serviceID := range profile.ServiceIDs {
		if _, ok := known[serviceID]; !ok {
			return AccessProfile{}, fmt.Errorf("%w: %s", ErrServiceNotFound, serviceID)
		}
	}
	if len(profile.DeviceIDs) > 0 {
		if c.deviceActive == nil {
			return AccessProfile{}, errors.New("device validation is not configured")
		}
		for _, deviceID := range profile.DeviceIDs {
			active, checkErr := c.deviceActive(ctx, deviceID)
			if checkErr != nil {
				return AccessProfile{}, checkErr
			}
			if !active {
				return AccessProfile{}, fmt.Errorf("%w: %s", ErrDeviceNotAllowed, deviceID)
			}
		}
	}
	profile.CreatedAt = c.now().UTC()
	if err := c.store.CreateProfile(ctx, profile); err != nil {
		return AccessProfile{}, err
	}
	return profile, nil
}

func (c *Catalog) Profiles(ctx context.Context) ([]AccessProfile, error) {
	return c.store.ListProfiles(ctx)
}

func validateService(item Service) error {
	if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.Name) == "" {
		return errors.New("service ID and name are required")
	}
	if item.Kind != KindWeb && item.Kind != KindNative {
		return fmt.Errorf("unsupported service kind %q", item.Kind)
	}

	if err := validateURL("service URL", item.URL, true); err != nil {
		return err
	}

	if item.NativeURL != "" {
		if err := validateURL("native URL", item.NativeURL, false); err != nil {
			return err
		}
	}

	if item.HealthURL != "" {
		if err := validateURL("health URL", item.HealthURL, true); err != nil {
			return err
		}
	}

	return nil
}

func validateURL(label, raw string, requireHTTPS bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%s must not contain credentials or fragments", label)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if requireHTTPS && scheme != "https" {
		return fmt.Errorf("%s must be HTTPS", label)
	}
	if !requireHTTPS && (scheme == "javascript" || scheme == "data" || scheme == "file" || scheme == "vbscript") {
		return fmt.Errorf("%s uses a disallowed scheme", label)
	}
	return nil
}

func uniqueSorted(values []string) []string {
	values = slices.Clone(values)
	slices.Sort(values)
	return slices.Compact(values)
}

type MemoryStore struct {
	mu       sync.Mutex
	services map[string]Service
	profiles map[string]AccessProfile
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{services: make(map[string]Service), profiles: make(map[string]AccessProfile)}
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
