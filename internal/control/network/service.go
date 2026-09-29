package network

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

var ErrAdvertisementNotFound = errors.New("network advertisement not found")

type Advertisement struct {
	ID              string       `json:"id"`
	GatewayDeviceID string       `json:"gateway_device_id"`
	Prefix          netip.Prefix `json:"prefix"`
	Resolver        netip.Addr   `json:"resolver"`
	DomainSuffix    string       `json:"domain_suffix"`
	Status          Status       `json:"status"`
	CreatedAt       time.Time    `json:"created_at"`
}
type AdvertisementRequest struct {
	ID              string
	GatewayDeviceID string
	Prefix          netip.Prefix
	Resolver        netip.Addr
	DomainSuffix    string
}
type Store interface {
	Save(context.Context, Advertisement) error
	SetStatus(context.Context, string, Status) error
	List(context.Context, *Status) ([]Advertisement, error)
}
type Service struct {
	store Store
	now   func() time.Time
}

func NewService(store Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}
}

func (s *Service) Advertise(ctx context.Context, request AdvertisementRequest) (Advertisement, error) {
	suffix := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(request.DomainSuffix)), ".")
	if request.ID == "" || request.GatewayDeviceID == "" || !request.Prefix.IsValid() || !request.Resolver.IsValid() || suffix == "" {
		return Advertisement{}, errors.New("complete route, resolver, and DNS suffix are required")
	}
	if !request.Prefix.Contains(request.Resolver) {
		return Advertisement{}, errors.New("DNS resolver must be inside the advertised prefix")
	}
	advertisement := Advertisement{ID: request.ID, GatewayDeviceID: request.GatewayDeviceID, Prefix: request.Prefix.Masked(), Resolver: request.Resolver, DomainSuffix: suffix, Status: StatusPending, CreatedAt: s.now().UTC()}
	if err := s.store.Save(ctx, advertisement); err != nil {
		return Advertisement{}, err
	}
	return advertisement, nil
}

func (s *Service) Approve(ctx context.Context, id string) error {
	return s.store.SetStatus(ctx, id, StatusApproved)
}

func (s *Service) Reject(ctx context.Context, id string) error {
	return s.store.SetStatus(ctx, id, StatusRejected)
}

func (s *Service) Approved(ctx context.Context) ([]Advertisement, error) {
	status := StatusApproved
	return s.store.List(ctx, &status)
}

func (s *Service) List(ctx context.Context) ([]Advertisement, error) { return s.store.List(ctx, nil) }

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
