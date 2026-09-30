package httpapi

import (
	"errors"
	"net/http"

	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
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
	items, err := s.services.Profiles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list access profiles")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": items})
}

func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var input controlservices.AccessProfile
	if !decodeJSON(w, r, &input) {
		return
	}
	profile, err := s.services.CreateProfile(r.Context(), input)
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
	if errors.Is(err, controlservices.ErrDuplicateID) {
		status = http.StatusConflict
		code = "conflict"
		message = "service or access profile already exists"
	}
	writeErrorCode(w, status, code, message)
}
