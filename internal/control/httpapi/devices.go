package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Role       devices.Role `json:"role"`
		TTLSeconds int64        `json:"ttl_seconds"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	token, err := s.devices.IssueEnrollmentToken(
		r.Context(),
		input.Role,
		time.Duration(input.TTLSeconds)*time.Second,
	)
	if err != nil {
		if errors.Is(err, devices.ErrInvalidTokenRequest) {
			writeErrorCode(
				w,
				http.StatusBadRequest,
				"invalid_request",
				"enrollment token request is invalid",
			)
		} else {
			writeErrorCode(
				w,
				http.StatusInternalServerError,
				"internal_error",
				"could not create enrollment token",
			)
		}
		return
	}
	writeJSON(w, http.StatusCreated, token)
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var input devices.EnrollRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	device, err := s.devices.Enroll(r.Context(), input)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, devices.ErrInvalidEnrollmentToken) {
			status = http.StatusUnauthorized
			writeErrorCode(
				w,
				status,
				"invalid_enrollment_token",
				"enrollment token is invalid or expired",
			)
		} else if errors.Is(err, devices.ErrInvalidEnrollment) {
			writeErrorCode(w, status, "invalid_request", "enrollment request is invalid")
		} else {
			writeErrorCode(
				w,
				http.StatusInternalServerError,
				"internal_error",
				"could not enroll device",
			)
		}
		return
	}
	writeJSON(w, http.StatusCreated, device)
}

func (s *Server) rotateCredential(w http.ResponseWriter, r *http.Request) {
	credential := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	device, err := s.devices.Authenticate(r.Context(), credential)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid device credential")
		return
	}
	rotated, err := s.devices.RotateCredential(r.Context(), device.ID, credential)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "device credential expired or revoked")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"credential": rotated})
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	list, err := s.devices.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list devices")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"devices": list})
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	// This mutation revokes control-plane credentials only. The signed snapshot
	// is owned by the trusted companion, so the companion must publish a
	// separate exact removal for an already-connected node to lose data-plane
	// access during a later control-plane outage.
	if err := s.devices.Revoke(r.Context(), r.PathValue("id")); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, devices.ErrDeviceNotFound) {
			status = http.StatusNotFound
			writeErrorCode(w, status, "device_not_found", "device not found")
		} else {
			writeErrorCode(w, status, "internal_error", "could not revoke device credentials")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
