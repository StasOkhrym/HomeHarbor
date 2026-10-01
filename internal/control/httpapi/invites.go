package httpapi

import (
	"net/http"

	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	"github.com/sokhrym/go-tunnels/internal/invite"
)

func (s *Server) submitInviteProof(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Permit invite.SignedPermit `json:"permit"`
		Proof  invite.Proof        `json:"proof"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}

	if err := s.invites.SubmitProof(r.Context(), input.Permit, input.Proof); err != nil {
		writeError(w, http.StatusBadRequest, "invalid invite proof")
		return
	}

	writeJSON(
		w,
		http.StatusAccepted,
		map[string]string{"status": string(controlinvites.StatusPending)},
	)
}

func (s *Server) getInvite(w http.ResponseWriter, r *http.Request) {
	record, err := s.invites.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "invite not found")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) approveInvite(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Approval invite.SignedApproval `json:"approval"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := s.invites.ApproveSigned(r.Context(), input.Approval)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid invite approval")
		return
	}
	// Approval returns no device credential to the companion. The enrolling
	// device must separately claim it with its own one-use possession proof.
	writeJSON(w, http.StatusOK, result)
}
