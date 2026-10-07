package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	controlinvites "github.com/StasOkhrym/homeharbor/internal/control/invites"
	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
	controlsnapshots "github.com/StasOkhrym/homeharbor/internal/control/snapshots"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// A failed read is not an empty collection. Keeping availability alongside
// values prevents an outage from looking like a fresh, unconfigured network.
type adminCollection[T any] struct {
	Items   []T
	Ready   bool
	Enabled bool
	Error   string
}

func (c adminCollection[T]) Count() string {
	if !c.Ready {
		return "—"
	}
	return strconv.Itoa(len(c.Items))
}

type adminPageModel struct {
	Page          string
	Title         string
	Description   string
	CSRF          string
	Notice        string
	Error         string
	Values        url.Values
	FieldErrors   map[string]string
	Devices       adminCollection[devices.Device]
	Services      adminCollection[controlservices.Service]
	Profiles      adminCollection[controlservices.AccessProfile]
	Routes        adminCollection[controlroutes.Advertisement]
	Audit         adminCollection[audit.Event]
	Device        *devices.Device
	Policy        acl.Snapshot
	PolicyReady   bool
	PolicyJSON    string
	PolicyError   string
	Signed        *snapshot.NetworkSnapshot
	SignedState   string
	Readiness     string
	PendingRoutes string
	Invite        *adminInviteModel
	InviteError   string
	InvitesReady  bool
	AuditLimit    int
	Preview       *adminPolicyPreview
	RevokeProof   string
	PolicyRows    []adminPolicyRow
}

// Only invite status metadata is rendered. Signed permits/proofs never enter
// browser forms; the companion and device perform those protocol operations.
type adminInviteModel struct {
	ID        string
	ProfileID string
	DeviceID  string
	Status    controlinvites.Status
}

func (m adminPageModel) Value(key string) string { return m.Values.Get(key) }
func (m adminPageModel) DeviceName(id string) string {
	for _, item := range m.Devices.Items {
		if item.ID == id {
			return item.Name
		}
	}
	return "Unavailable device"
}

func (m adminPageModel) ServiceName(id string) string {
	for _, item := range m.Services.Items {
		if item.ID == id {
			return item.Name
		}
	}
	return "Unavailable service"
}

func (m adminPageModel) Selected(key, value string) bool {
	for _, item := range m.Values[key] {
		if item == value {
			return true
		}
	}
	return false
}

var adminTitles = map[string][2]string{
	"overview": {"Overview", "Your network, without the guesswork."},
	"setup": {
		"Set up your network",
		"Follow the steps without losing access to the rest of the panel.",
	},
	"devices": {
		"Devices",
		"Manage registration and authentication. Tunnel connectivity is reported separately.",
	},
	"services": {"Services", "A simple catalog of your private applications."},
	"access": {
		"Access",
		"Manage profiles and default-deny rules. Saved settings are not signed access grants.",
	},
	"network": {"Network", "Review LAN routes and split DNS settings before approving them."},
	"invites": {
		"Invites",
		"Signed invites use your trusted companion. Legacy tokens are a separate mechanism.",
	},
	"activity": {"Activity", "Recent audit events from the control plane."},
	"security": {
		"Security",
		"Your passkey, recovery codes and network signing key have separate roles.",
	},
}

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	s.adminView("overview")(w, r)
}

func (s *Server) adminView(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		model, status := s.loadAdminPage(r, page)
		s.renderAdmin(w, status, model)
	}
}

func loadAdminCollection[T any](
	ctx context.Context,
	label string,
	read func(context.Context) ([]T, error),
) adminCollection[T] {
	result := adminCollection[T]{Enabled: read != nil}
	if read == nil {
		result.Error = label + " is not configured"
		return result
	}
	items, err := read(ctx)
	if err != nil {
		result.Error = label + " could not be loaded"
		return result
	}
	result.Items, result.Ready = items, true
	return result
}

func (s *Server) loadAdminPage(r *http.Request, page string) (adminPageModel, int) {
	metadata := adminTitles[page]
	model := adminPageModel{
		Page:          page,
		Title:         metadata[0],
		Description:   metadata[1],
		CSRF:          csrfFormToken(r),
		Notice:        adminNotices[r.URL.Query().Get("notice")],
		Values:        url.Values{},
		FieldErrors:   map[string]string{},
		PendingRoutes: "—",
		SignedState:   "Signed configuration is not configured",
		Readiness:     "Readiness check is not configured",
		AuditLimit:    defaultAuditLimit,
		InvitesReady:  s.invites != nil,
	}
	ctx := r.Context()
	if s.devices != nil {
		model.Devices = loadAdminCollection(ctx, "Devices", s.devices.List)
	} else {
		model.Devices.Error = "Devices are not configured"
	}
	if s.services != nil &&
		(page == "overview" || page == "setup" || page == "services" || page == "access" || page == "invites") {
		model.Services = loadAdminCollection(ctx, "Services", s.services.List)
		model.Profiles = loadAdminCollection(ctx, "Access profiles", s.services.Profiles)
	} else if s.services == nil {
		model.Services.Error = "Services are not configured"
		model.Profiles.Error = "Access profiles are not configured"
	}
	if s.routes != nil && (page == "overview" || page == "setup" || page == "network") {
		model.Routes = loadAdminCollection(ctx, "Routes", s.routes.List)
		if model.Routes.Ready {
			count := 0
			for _, route := range model.Routes.Items {
				if route.Status == controlroutes.StatusPending {
					count++
				}
			}
			model.PendingRoutes = strconv.Itoa(count)
		}
	} else if s.routes == nil {
		model.Routes.Error = "Routes are not configured"
	}
	if page == "access" {
		s.loadAdminPolicy(ctx, &model)
	}
	if page == "overview" || page == "setup" || page == "security" {
		s.loadAdminSignedState(ctx, &model)
		if s.ready != nil {
			model.Readiness = "Ready"
			if err := s.ready(ctx); err != nil {
				model.Readiness = "Control dependencies are unavailable"
			}
		}
	}
	status := http.StatusOK
	if page == "services" || page == "access" || page == "network" {
		id, err := newBrowserID()
		if err != nil {
			model.Error = "A form could not be prepared. Please reload."
			return model, http.StatusServiceUnavailable
		}
		// Carry the ID through validation and retries: repeating the same form
		// cannot silently create another record after a lost response.
		model.Values.Set("id", id)
	}
	switch page {
	case "services":
		if !model.Services.Ready {
			status = http.StatusServiceUnavailable
		}
	case "network":
		if !model.Routes.Ready || !model.Devices.Ready {
			status = http.StatusServiceUnavailable
		}
	case "devices":
		if !model.Devices.Ready {
			status = http.StatusServiceUnavailable
		} else if id := r.PathValue("id"); id != "" {
			for index := range model.Devices.Items {
				if model.Devices.Items[index].ID == id {
					model.Device = &model.Devices.Items[index]
					model.Title = model.Device.Name
				}
			}
			if model.Device == nil {
				model.Error, status = "Device not found", http.StatusNotFound
			} else if s.actionConfirmation != nil {
				payload, _ := json.Marshal(
					browserAction{Operation: "revoke-device", Target: model.Device.ID},
				)
				model.RevokeProof = s.actionConfirmation.SignAction(model.CSRF, payload)
			}
		}
	case "activity":
		status = s.loadAdminAudit(r, &model)
	case "invites":
		s.loadAdminInvite(r, &model)
	}
	return model, status
}

func (s *Server) loadAdminPolicy(ctx context.Context, model *adminPageModel) {
	model.PolicyError = "Policy is not configured"
	if s.policy == nil {
		return
	}
	value, err := s.policy.Latest(ctx)
	if err != nil {
		model.PolicyError = "Policy could not be loaded"
		return
	}
	if value.Rules == nil {
		value.Rules = []acl.Rule{}
	}
	encoded, err := json.MarshalIndent(value.Rules, "", "  ")
	if err != nil {
		model.PolicyError = "Policy could not be displayed"
		return
	}
	model.Policy, model.PolicyJSON, model.PolicyReady = value, string(encoded), true
	model.PolicyError = ""
	model.Values.Set("rules", model.PolicyJSON)
	for _, rule := range value.Rules {
		model.PolicyRows = append(model.PolicyRows, adminPolicyRow{
			ID:          rule.ID,
			Source:      rule.SourceDeviceID,
			Destination: rule.Destination.String(),
			Protocol:    string(rule.Protocol),
			From:        strconv.Itoa(int(rule.PortFrom)),
			To:          strconv.Itoa(int(rule.PortTo)),
		})
	}
	model.PolicyRows = append(model.PolicyRows, adminPolicyRow{Protocol: "tcp"})
}

func (s *Server) loadAdminSignedState(ctx context.Context, model *adminPageModel) {
	if s.snapshots == nil {
		return
	}
	envelope, err := s.snapshots.Latest(ctx)
	if errors.Is(err, controlsnapshots.ErrSnapshotUnavailable) {
		model.SignedState = "No signed configuration has been published"
		return
	}
	if err != nil {
		model.SignedState = "Signed configuration could not be loaded"
		return
	}
	value, err := snapshot.Decode(envelope)
	if err != nil {
		model.SignedState = "Signed configuration could not be displayed"
		return
	}
	model.Signed = &value
	model.SignedState = fmt.Sprintf("Signed revision %d · Published", value.Revision)
}

func (s *Server) loadAdminInvite(r *http.Request, model *adminPageModel) {
	id := strings.TrimSpace(r.URL.Query().Get("invite_id"))
	model.Values.Set("invite_id", id)
	if id == "" || s.invites == nil {
		return
	}
	if len(id) > 128 {
		model.InviteError = "Enter a valid invite ID, not an invite link or code."
		return
	}
	record, err := s.invites.Get(r.Context(), id)
	if errors.Is(err, controlinvites.ErrInviteNotFound) {
		model.InviteError = "Invite not found. It may not have received a device proof yet."
	} else if err != nil {
		model.InviteError = "Invite status could not be loaded. Try again shortly."
	} else {
		model.Invite = &adminInviteModel{
			ID:        record.InviteID,
			ProfileID: record.ProfileID,
			DeviceID:  record.DeviceID,
			Status:    record.Status,
		}
	}
}

func (s *Server) loadAdminAudit(r *http.Request, model *adminPageModel) int {
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			model.Error = "Choose a positive number of audit events."
			return http.StatusBadRequest
		}
		model.AuditLimit = min(limit, maxAuditLimit)
	}
	if s.audit == nil {
		model.Audit.Error = "Activity is not configured"
		return http.StatusServiceUnavailable
	}
	model.Audit = loadAdminCollection(
		r.Context(),
		"Activity",
		func(ctx context.Context) ([]audit.Event, error) {
			return s.audit.List(ctx, model.AuditLimit)
		},
	)
	if !model.Audit.Ready {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

var adminNotices = map[string]string{
	"service-created": "Service saved to the catalog. This does not grant network access.",
	"profile-created": "Access profile saved. Signed network configuration is a separate step.",
	"route-created":   "Route saved and awaiting approval.",
	"route-approved":  "Route approved in control. Gateway application is not confirmed.",
	"route-rejected":  "Route rejected in control. Existing signed grants are unchanged.",
	"policy-updated":  "Policy saved. This is not a signed network update.",
	"device-revoked":  "Credentials revoked. Use your trusted companion to remove the signed access grant.",
}
