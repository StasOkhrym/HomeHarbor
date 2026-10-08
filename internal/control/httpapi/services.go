package httpapi

import (
	"errors"
	"net/http"

	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
)

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	items, err := s.services.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list services")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"services": items})
}

func (s *Server) createService(w http.ResponseWriter, r *http.Request) {
	var input controlservices.Service
	if !decodeJSON(w, r, &input) {
		return
	}

	item, err := s.services.Create(r.Context(), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	items, err := s.profiles.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list access profiles")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"profiles": items})
}

func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var input profiles.AccessProfile
	if !decodeJSON(w, r, &input) {
		return
	}

	profile, err := s.profiles.Create(r.Context(), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, profile)
}

func writeServiceError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	code := "invalid_request"
	message := "service or access profile request is invalid"
	if errors.Is(err, controlservices.ErrDuplicateID) || errors.Is(err, profiles.ErrDuplicateID) {
		status = http.StatusConflict
		code = "conflict"
		message = "service or access profile already exists"
	}

	writeErrorCode(w, status, code, message)
}

func (s *Server) listAvailableServices(w http.ResponseWriter, r *http.Request) {
	device, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "device authentication required")
		return
	}

	items, err := s.services.ListForDevice(r.Context(), device.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list available services")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"services": items})
}
