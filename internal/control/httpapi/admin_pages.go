package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
	webadmin "github.com/StasOkhrym/homeharbor/internal/web/admin"
)

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	s.adminView("overview")(w, r)
}

func (s *Server) adminView(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		model, status := s.loadAdminPage(r, page)
		s.renderAdmin(w, status, model)
	}
}

func (s *Server) loadAdminPage(r *http.Request, page string) (webadmin.Page, int) {
	model := webadmin.NewPage(page, csrfFormToken(r), r.URL.Query().Get("notice"))
	model.InvitesReady = s.invites != nil
	ctx := r.Context()
	needsDevices := page == "overview" || page == "setup" || page == "devices" ||
		page == "access" || page == "network" || page == "invites"
	needsServices := page == "overview" || page == "services" || page == "access"
	needsProfiles := page == "overview" || page == "access"
	needsRoutes := page == "overview" || page == "setup" || page == "network"
	if needsDevices {
		if s.devices != nil {
			model.Devices = webadmin.LoadCollection(ctx, "Devices", s.devices.List)
		} else {
			model.Devices.Error = "Devices are not configured"
		}
	}
	if needsServices {
		if s.services != nil {
			model.Services = webadmin.LoadCollection(ctx, "Services", s.services.List)
		} else {
			model.Services.Error = "Services are not configured"
		}
	}
	if needsProfiles {
		if s.profiles != nil {
			model.Profiles = webadmin.LoadCollection(ctx, "Access profiles", s.profiles.List)
		} else {
			model.Profiles.Error = "Access profiles are not configured"
		}
	}
	if needsRoutes && s.routes != nil {
		model.Routes = webadmin.LoadCollection(ctx, "Routes", s.routes.List)
		if model.Routes.Ready {
			count := 0
			for _, route := range model.Routes.Items {
				if route.Status == controlroutes.StatusPending {
					count++
				}
			}
			model.PendingRoutes = strconv.Itoa(count)
		}
	} else if needsRoutes {
		model.Routes.Error = "Routes are not configured"
	}
	if page == "access" {
		webadmin.LoadPolicy(ctx, s.policy, &model)
	}
	if page == "overview" || page == "setup" || page == "security" {
		webadmin.LoadSignedState(ctx, s.snapshots, &model)
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
		model.Activity, status = webadmin.LoadActivity(r.Context(), s.audit, r.URL.Query())
	case "invites":
		webadmin.LoadInvite(ctx, r.URL.Query().Get("invite_id"), s.invites, &model)
	}
	return model, status
}
