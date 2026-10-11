package admin

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
)

func (s *Handler) createRouteForm(w http.ResponseWriter, r *http.Request) {
	if s.routes == nil {
		s.adminFormError(
			w,
			r,
			"network",
			http.StatusServiceUnavailable,
			"form",
			"Routes are not configured.",
		)
		return
	}

	prefix, err := netip.ParsePrefix(strings.TrimSpace(r.FormValue("prefix")))
	if err != nil || prefix.Bits() == 0 {
		s.adminFormError(
			w,
			r,
			"network",
			http.StatusUnprocessableEntity,
			"prefix",
			"Enter a non-default LAN CIDR, such as 192.168.50.0/24.",
		)
		return
	}

	resolver, err := netip.ParseAddr(strings.TrimSpace(r.FormValue("resolver")))
	if err != nil || !prefix.Contains(resolver) {
		s.adminFormError(
			w,
			r,
			"network",
			http.StatusUnprocessableEntity,
			"resolver",
			"Enter a DNS resolver IP within the LAN CIDR.",
		)
		return
	}

	id, err := browserFormID(r)
	if err != nil {
		status, message := browserIDError(err)
		s.adminFormError(w, r, "network", status, "id", message)
		return
	}

	item := controlroutes.AdvertisementRequest{
		ID:              id,
		GatewayDeviceID: strings.TrimSpace(r.FormValue("gateway_device_id")),
		Prefix:          prefix,
		Resolver:        resolver,
		DomainSuffix:    strings.TrimSpace(r.FormValue("domain_suffix")),
	}
	if _, err = s.routes.Advertise(r.Context(), item); err != nil {
		status, field, message := http.StatusServiceUnavailable, "form", "The route could not be saved. Try again shortly."
		if errors.Is(err, controlroutes.ErrInvalidAdvertisement) {
			status, field, message = http.StatusUnprocessableEntity, "domain_suffix", "Check the gateway, resolver and concrete private DNS suffix."
		}

		s.adminFormError(w, r, "network", status, field, message)
		return
	}

	redirectAdmin(w, r, "route-created")
}

func (s *Handler) approveRouteForm(w http.ResponseWriter, r *http.Request) {
	s.setRouteApproval(w, r, true)
}

func (s *Handler) rejectRouteForm(w http.ResponseWriter, r *http.Request) {
	s.setRouteApproval(w, r, false)
}

func (s *Handler) setRouteApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	if s.routes == nil {
		s.adminFormError(
			w,
			r,
			"network",
			http.StatusServiceUnavailable,
			"form",
			"Routes are not configured.",
		)
		return
	}

	var err error
	id := r.PathValue("id")
	if id == "" {
		// Browser actions carry opaque IDs in the body so path normalization
		// cannot change their target. Path aliases keep their existing contract.
		id = r.FormValue("route_id")
	}

	notice := "route-rejected"
	if approve {
		err, notice = s.routes.Approve(r.Context(), id), "route-approved"
	} else {
		err = s.routes.Reject(r.Context(), id)
	}

	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, controlroutes.ErrAdvertisementNotFound) {
			status = http.StatusNotFound
		}

		s.adminFormError(
			w,
			r,
			"network",
			status,
			"form",
			"The route status could not be changed. Reload and review it.",
		)
		return
	}

	redirectAdmin(w, r, notice)
}
