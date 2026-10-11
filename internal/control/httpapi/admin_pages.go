package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	controlinvites "github.com/StasOkhrym/homeharbor/internal/control/invites"
	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
	controlsnapshots "github.com/StasOkhrym/homeharbor/internal/control/snapshots"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
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
		model.Activity, status = webadmin.LoadActivity(r.Context(), s.audit, r.URL.Query())
	case "invites":
		s.loadAdminInvite(r, &model)
	}
	return model, status
}

func (s *Server) loadAdminPolicy(ctx context.Context, model *webadmin.Page) {
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
		model.PolicyRows = append(model.PolicyRows, webadmin.PolicyRow{
			ID:          rule.ID,
			Source:      rule.SourceDeviceID,
			Destination: rule.Destination.String(),
			Protocol:    string(rule.Protocol),
			From:        strconv.Itoa(int(rule.PortFrom)),
			To:          strconv.Itoa(int(rule.PortTo)),
		})
	}
	model.PolicyRows = append(model.PolicyRows, webadmin.PolicyRow{Protocol: "tcp"})
}

func (s *Server) loadAdminSignedState(ctx context.Context, model *webadmin.Page) {
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

func (s *Server) loadAdminInvite(r *http.Request, model *webadmin.Page) {
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
		model.Invite = &webadmin.Invite{
			ID:        record.InviteID,
			ProfileID: record.ProfileID,
			DeviceID:  record.DeviceID,
			Status:    record.Status,
		}
	}
}
