// Package services owns the user-facing service catalog.
// The policy compiler consumes these concepts later; the catalog itself never
// exposes database tables to HTTP handlers.
package services

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Kind string

const (
	KindWeb    Kind = "web"
	KindNative Kind = "native"
)

var ErrDuplicateID = errors.New("service ID already exists")

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

type Repository interface {
	CreateService(context.Context, Service) error
	ListServices(context.Context) ([]Service, error)
	ListServicesForDevice(context.Context, string) ([]Service, error)
}

type Catalog struct {
	store Repository
	now   func() time.Time
}

func NewService(store Repository, now func() time.Time) *Catalog {
	if now == nil {
		now = time.Now
	}

	return &Catalog{store: store, now: now}
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

// ListForDevice returns only services granted through an explicit profile
// membership. An authenticated device with no profile receives an empty list;
// callers must not interpret catalog visibility as a replacement for the
// signed snapshot ACL enforced by the gateway.
func (c *Catalog) ListForDevice(ctx context.Context, deviceID string) ([]Service, error) {
	if strings.TrimSpace(deviceID) == "" {
		return nil, errors.New("device ID is required")
	}

	return c.store.ListServicesForDevice(ctx, deviceID)
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
	if !requireHTTPS &&
		(scheme == "javascript" || scheme == "data" || scheme == "file" || scheme == "vbscript") {
		return fmt.Errorf("%s uses a disallowed scheme", label)
	}

	return nil
}
