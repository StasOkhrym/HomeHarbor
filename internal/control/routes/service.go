// Package routes manages gateway advertisements and split-DNS routes.
package routes

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

var (
	ErrAdvertisementNotFound = errors.New("network advertisement not found")
	ErrInvalidAdvertisement  = errors.New("invalid network advertisement")
)

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
type Repository interface {
	Save(context.Context, Advertisement) error
	SetStatus(context.Context, string, Status) error
	List(context.Context, *Status) ([]Advertisement, error)
}
type Service struct {
	store Repository
	now   func() time.Time
}

func NewService(store Repository, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}

	return &Service{store: store, now: now}
}

func (s *Service) Advertise(ctx context.Context, request AdvertisementRequest) (Advertisement, error) {
	suffix := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(request.DomainSuffix)), ".")
	if request.ID == "" || request.GatewayDeviceID == "" || !request.Prefix.IsValid() || request.Prefix.Bits() == 0 ||
		!request.Resolver.IsValid() ||
		request.Resolver.IsUnspecified() ||
		!validDomainSuffix(suffix) {
		return Advertisement{}, fmt.Errorf(
			"%w: complete route, resolver, and DNS suffix are required",
			ErrInvalidAdvertisement,
		)
	}
	if !request.Prefix.Contains(request.Resolver) {
		return Advertisement{}, fmt.Errorf(
			"%w: DNS resolver must be inside the advertised prefix",
			ErrInvalidAdvertisement,
		)
	}
	advertisement := Advertisement{
		ID:              request.ID,
		GatewayDeviceID: request.GatewayDeviceID,
		Prefix:          request.Prefix.Masked(),
		Resolver:        request.Resolver,
		DomainSuffix:    suffix,
		Status:          StatusPending,
		CreatedAt:       s.now().UTC(),
	}
	if err := s.store.Save(ctx, advertisement); err != nil {
		return Advertisement{}, err
	}
	return advertisement, nil
}

// validDomainSuffix mirrors the route-only resolver contract: only a concrete
// DNS suffix may be installed, never a wildcard, command fragment, or empty
// label. Canonicalizing before this check makes equivalent trailing-dot input
// persist as one stable value and keeps snapshot comparisons deterministic.
func validDomainSuffix(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
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
