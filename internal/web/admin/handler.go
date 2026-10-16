package admin

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
	"github.com/StasOkhrym/homeharbor/internal/control/routes"
	"github.com/StasOkhrym/homeharbor/internal/control/services"
	websession "github.com/StasOkhrym/homeharbor/internal/web/session"
)

type DeviceManager interface {
	List(context.Context) ([]devices.Device, error)
	IssueEnrollmentToken(context.Context, devices.Role, time.Duration) (devices.IssuedToken, error)
	Revoke(context.Context, string) error
}

type RouteManager interface {
	List(context.Context) ([]routes.Advertisement, error)
	Advertise(context.Context, routes.AdvertisementRequest) (routes.Advertisement, error)
	Approve(context.Context, string) error
	Reject(context.Context, string) error
}

type ServiceManager interface {
	List(context.Context) ([]services.Service, error)
	Create(context.Context, services.Service) (services.Service, error)
}

type ProfileManager interface {
	List(context.Context) ([]profiles.AccessProfile, error)
	Create(context.Context, profiles.AccessProfile) (profiles.AccessProfile, error)
}

type PolicyManager interface {
	PolicyReader
	ReplaceIfRevision(context.Context, uint64, []acl.Rule) (acl.Snapshot, error)
}

// Dependencies are browser-only capabilities. The composition root supplies
// domain services; the JSON transport has no dependency on this adapter.
type Dependencies struct {
	Devices            DeviceManager
	Routes             RouteManager
	Services           ServiceManager
	Profiles           ProfileManager
	Policy             PolicyManager
	Invites            InviteReader
	Snapshots          SnapshotReader
	Audit              ActivityReader
	Telemetry          ConnectionReader
	Ready              func(context.Context) error
	ActionConfirmation websession.ActionConfirmation
	InvalidateDevice   func(string)
	Logger             *slog.Logger
}

type Handler struct {
	devices            DeviceManager
	routes             RouteManager
	services           ServiceManager
	profiles           ProfileManager
	policy             PolicyManager
	invites            InviteReader
	snapshots          SnapshotReader
	audit              ActivityReader
	telemetry          ConnectionReader
	ready              func(context.Context) error
	actionConfirmation websession.ActionConfirmation
	invalidateDevice   func(string)
	logger             *slog.Logger
}

func NewHandler(deps Dependencies) *Handler {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		devices: deps.Devices, routes: deps.Routes, services: deps.Services,
		profiles: deps.Profiles, policy: deps.Policy, invites: deps.Invites,
		snapshots: deps.Snapshots, audit: deps.Audit, telemetry: deps.Telemetry, ready: deps.Ready,
		actionConfirmation: deps.ActionConfirmation,
		invalidateDevice:   deps.InvalidateDevice, logger: logger,
	}
}

// Routes are mounted behind the control server's session and mutation
// authorization middleware.
func (h *Handler) Routes() http.Handler {
	router := chi.NewRouter()
	router.Get("/", h.adminDashboard)
	for _, page := range []string{
		"setup", "devices", "services", "access", "network", "invites", "activity", "security", "connections", "settings",
	} {
		router.Get("/"+page, h.adminView(page))
	}
	router.Get("/activity/fragment", ActivityFragment(h.audit, h.logger))
	router.Get("/connections/fragment", h.connectionsFragment)
	router.Get("/devices/{id}", h.adminView("devices"))
	router.Post("/enrollment-tokens", h.issueEnrollmentTokenForm)
	router.Post("/devices/{id}/revoke", h.revokeDeviceForm)
	if h.routes != nil {
		router.Post("/routes", h.createRouteForm)
		router.Post("/routes/approve", h.approveRouteForm)
		router.Post("/routes/reject", h.rejectRouteForm)
		router.Post("/routes/{id}/approve", h.approveRouteForm)
		router.Post("/routes/{id}/reject", h.rejectRouteForm)
	}
	router.Post("/services", h.createServiceForm)
	router.Post("/access-profiles", h.createProfileForm)
	router.Post("/policy", h.replacePolicyForm)
	router.Post("/policy/preview", h.previewPolicyForm)
	return router
}
