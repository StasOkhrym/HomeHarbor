package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sokhrym/go-tunnels/internal/app/control/workflows"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/control/invites"
)

// ActivationChallenger and ActivationClaimer are the only workflow ports
// needed by these handlers. The parent mounts and rate-limits both callbacks.
type (
	ActivationChallenger interface {
		Challenge(context.Context, string) (workflows.ClaimChallenge, error)
	}
	ActivationClaimer interface {
		Claim(context.Context, string, workflows.ClaimProof) (workflows.ClaimResult, error)
	}
	ActivationHandler struct {
		challenges ActivationChallenger
		claims     ActivationClaimer
	}
)

func NewActivationHandler(
	challenges ActivationChallenger,
	claims ActivationClaimer,
) *ActivationHandler {
	return &ActivationHandler{challenges: challenges, claims: claims}
}

func activationInviteID(r *http.Request) string {
	if id := r.PathValue("id"); id != "" {
		return id
	}

	return chi.URLParam(r, "id")
}

// Challenge handles POST /api/v1/invites/{id}/challenge. It returns no bearer
// secret and waits for root-signed topology by reporting 409 when not ready.
func (h *ActivationHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	id := activationInviteID(r)
	if id == "" {
		writeError(w, http.StatusBadRequest, "invite ID required")
		return
	}
	if h.challenges == nil {
		writeError(w, http.StatusServiceUnavailable, "activation unavailable")
		return
	}

	c, err := h.challenges.Challenge(r.Context(), id)
	if err != nil {
		activationError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, c)
}

// Claim handles POST /api/v1/invites/{id}/claim. The sole secret response goes
// to the device that proves Ed25519 possession, never to the companion.
func (h *ActivationHandler) Claim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	id := activationInviteID(r)
	if id == "" {
		writeError(w, http.StatusBadRequest, "invite ID required")
		return
	}
	var proof workflows.ClaimProof
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		writeError(w, http.StatusBadRequest, "invalid claim body")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid claim body")
		return
	}
	if h.claims == nil {
		writeError(w, http.StatusServiceUnavailable, "activation unavailable")
		return
	}
	result, err := h.claims.Claim(r.Context(), id, proof)
	if err != nil {
		activationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func activationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, workflows.ErrNotReady):
		writeError(w, http.StatusConflict, "activation not ready")
	case errors.Is(err, workflows.ErrInvalidClaim):
		writeErrorCode(
			w,
			http.StatusBadRequest,
			"invalid_activation_claim",
			"invalid activation claim",
		)
	case errors.Is(err, invites.ErrInviteNotFound):
		writeError(w, http.StatusNotFound, "invite not found")
	case errors.Is(err, devices.ErrDeviceNotFound),
		errors.Is(err, invites.ErrInviteBlocked),
		errors.Is(err, invites.ErrInviteConsumed):
		writeError(w, http.StatusForbidden, "activation unavailable")
	default:
		writeError(w, http.StatusServiceUnavailable, "activation unavailable")
	}
}
