package httpapi

import (
	"errors"
	"net/http"
	"net/netip"

	controlroutes "github.com/sokhrym/go-tunnels/internal/control/routes"
)

func (s *Server) advertiseRoute(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID              string `json:"id"`
		GatewayDeviceID string `json:"gateway_device_id"`
		Prefix          string `json:"prefix"`
		Resolver        string `json:"resolver"`
		DomainSuffix    string `json:"domain_suffix"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	prefix, err := netip.ParsePrefix(input.Prefix)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid prefix")
		return
	}
	resolver, err := netip.ParseAddr(input.Resolver)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resolver")
		return
	}
	item, err := s.routes.Advertise(r.Context(), controlroutes.AdvertisementRequest{ID: input.ID, GatewayDeviceID: input.GatewayDeviceID, Prefix: prefix, Resolver: resolver, DomainSuffix: input.DomainSuffix})
	if err != nil {
		if errors.Is(err, controlroutes.ErrInvalidAdvertisement) {
			writeErrorCode(w, http.StatusBadRequest, "invalid_route", "route advertisement is invalid")
		} else {
			writeErrorCode(w, http.StatusInternalServerError, "internal_error", "could not advertise route")
		}
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	items, err := s.routes.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list routes")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"routes": items})
}

func (s *Server) approveRoute(w http.ResponseWriter, r *http.Request) {
	if err := s.routes.Approve(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, controlroutes.ErrAdvertisementNotFound) {
			writeErrorCode(w, http.StatusNotFound, "route_not_found", "route advertisement not found")
		} else {
			writeErrorCode(w, http.StatusInternalServerError, "internal_error", "could not approve route")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rejectRoute(w http.ResponseWriter, r *http.Request) {
	if err := s.routes.Reject(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, controlroutes.ErrAdvertisementNotFound) {
			writeErrorCode(w, http.StatusNotFound, "route_not_found", "route advertisement not found")
		} else {
			writeErrorCode(w, http.StatusInternalServerError, "internal_error", "could not reject route")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
