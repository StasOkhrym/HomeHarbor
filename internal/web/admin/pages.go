package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
)

func (s *Handler) adminDashboard(w http.ResponseWriter, r *http.Request) {
	s.adminView("overview")(w, r)
}

func (s *Handler) adminView(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		model, status := s.loadAdminPage(r, page)
		s.renderAdmin(w, status, model)
	}
}

// Each page asks only for the state it displays. A failed collection remains
// independently visible, so an outage never looks like an empty catalog.
func (s *Handler) loadAdminPage(r *http.Request, page string) (Page, int) {
	model := NewPage(page, csrfFormToken(r), r.URL.Query().Get("notice"))
	model.InvitesReady = s.invites != nil
	ctx := r.Context()
	switch page {
	case "overview":
		s.loadDevices(ctx, &model)
		s.loadServices(ctx, &model)
		s.loadRoutes(ctx, &model)
		s.loadSignedReadiness(ctx, &model)
	case "setup":
		s.loadDevices(ctx, &model)
		s.loadRoutes(ctx, &model)
		s.loadSignedReadiness(ctx, &model)
	case "devices":
		s.loadDevices(ctx, &model)
		if !model.Devices.Ready {
			return model, http.StatusServiceUnavailable
		}
		s.loadDeviceDetail(r.PathValue("id"), &model)
		if r.PathValue("id") != "" && model.Device == nil {
			model.Error = "Device not found"
			return model, http.StatusNotFound
		}
	case "services":
		s.loadServices(ctx, &model)
		if !prepareFormID(&model) || !model.Services.Ready {
			return model, http.StatusServiceUnavailable
		}
	case "access":
		s.loadDevices(ctx, &model)
		s.loadServices(ctx, &model)
		s.loadProfiles(ctx, &model)
		LoadPolicy(ctx, s.policy, &model)
		if !prepareFormID(&model) {
			return model, http.StatusServiceUnavailable
		}
	case "network":
		s.loadDevices(ctx, &model)
		s.loadRoutes(ctx, &model)
		if !prepareFormID(&model) || !model.Routes.Ready || !model.Devices.Ready {
			return model, http.StatusServiceUnavailable
		}
	case "invites":
		s.loadDevices(ctx, &model)
		LoadInvite(ctx, r.URL.Query().Get("invite_id"), s.invites, &model)
	case "connections":
		status := s.loadConnections(r, &model)
		return model, status
	case "activity":
		var status int
		model.Activity, status = LoadActivity(ctx, s.audit, r.URL.Query())
		return model, status
	case "security":
		s.loadSignedReadiness(ctx, &model)
	}
	return model, http.StatusOK
}

func (s *Handler) loadDevices(ctx context.Context, model *Page) {
	if s.devices == nil {
		model.Devices.Error = "Devices are not configured"
		return
	}

	model.Devices = LoadCollection(ctx, "Devices", s.devices.List)
}

func (s *Handler) loadServices(ctx context.Context, model *Page) {
	if s.services == nil {
		model.Services.Error = "Services are not configured"
		return
	}

	model.Services = LoadCollection(ctx, "Services", s.services.List)
}

func (s *Handler) loadProfiles(ctx context.Context, model *Page) {
	if s.profiles == nil {
		model.Profiles.Error = "Access profiles are not configured"
		return
	}

	model.Profiles = LoadCollection(ctx, "Access profiles", s.profiles.List)
}

func (s *Handler) loadRoutes(ctx context.Context, model *Page) {
	if s.routes == nil {
		model.Routes.Error = "Routes are not configured"
		return
	}

	model.Routes = LoadCollection(ctx, "Routes", s.routes.List)
	if !model.Routes.Ready {
		return
	}

	count := 0
	for _, route := range model.Routes.Items {
		if route.Status == controlroutes.StatusPending {
			count++
		}
	}

	model.PendingRoutes = strconv.Itoa(count)
}

func (s *Handler) loadSignedReadiness(ctx context.Context, model *Page) {
	LoadSignedState(ctx, s.snapshots, model)
	if s.ready == nil {
		return
	}

	model.Readiness = "Ready"

	if err := s.ready(ctx); err != nil {
		model.Readiness = "Control dependencies are unavailable"
	}
}

func prepareFormID(model *Page) bool {
	id, err := newBrowserID()
	if err != nil {
		model.Error = "A form could not be prepared. Please reload."
		return false
	}

	// Reusing the same submitted form cannot create another record after a
	// lost response.
	model.Values.Set("id", id)
	return true
}

func (s *Handler) loadDeviceDetail(id string, model *Page) {
	if id == "" {
		return
	}

	for index := range model.Devices.Items {
		if model.Devices.Items[index].ID == id {
			model.Device = &model.Devices.Items[index]
			model.Title = model.Device.Name
		}
	}

	if model.Device != nil && s.actionConfirmation != nil {
		payload, _ := json.Marshal(browserAction{Operation: "revoke-device", Target: id})
		model.RevokeProof = s.actionConfirmation.SignAction(model.CSRF, payload)
	}
}
