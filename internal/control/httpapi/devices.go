package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
	w.Header().Set("Cache-Control", "no-store")
	var input protocol.EnrollmentRequest
	if !decodeJSON(w, r, &input) {
		return
	}

	device, err := s.devices.Enroll(
		r.Context(),
		devices.EnrollRequest{
			Token:              input.Token,
			Name:               input.Name,
			IdentityPublicKey:  input.IdentityPublicKey,
			WireGuardPublicKey: input.WireGuardPublicKey,
		},
	)
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

	writeJSON(w, http.StatusCreated, enrolledDevice(device))
}

func (s *Server) rotateCredential(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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

	writeJSON(w, http.StatusOK, rotated)
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

func enrolledDevice(d devices.Device) protocol.EnrolledDevice {
	return protocol.EnrolledDevice{
		ID:                  d.ID,
		Name:                d.Name,
		Role:                string(d.Role),
		Status:              string(d.Status),
		IdentityPublicKey:   d.IdentityPublicKey,
		WireGuardPublicKey:  d.WireGuardPublicKey,
		CreatedAt:           d.CreatedAt,
		RevokedAt:           d.RevokedAt,
		Credential:          d.Credential,
		CredentialExpiresAt: d.CredentialExpiresAt,
	}
}

func (s *Server) credentialChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input struct {
		DeviceID string `json:"device_id"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}

	c, err := s.recovery.Challenge(r.Context(), input.DeviceID)
	if err != nil {
		credentialRecoveryError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, c)
}

func (s *Server) recoverCredential(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var proof protocol.CredentialProof
	if !decodeJSON(w, r, &proof) {
		return
	}

	lease, err := s.recovery.Recover(r.Context(), proof)
	if err != nil {
		credentialRecoveryError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, lease)
}

func credentialRecoveryError(w http.ResponseWriter, err error) {
	if errors.Is(err, protocol.ErrInvalidCredentialProof) {
		writeErrorCode(
			w,
			http.StatusUnauthorized,
			"invalid_credential_proof",
			"invalid credential proof",
		)
		return
	}

	writeErrorCode(
		w,
		http.StatusServiceUnavailable,
		"recovery_unavailable",
		"credential recovery unavailable",
	)
}
