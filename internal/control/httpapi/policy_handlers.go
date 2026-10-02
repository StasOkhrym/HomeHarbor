package httpapi

import (
	"net/http"

	"github.com/StasOkhrym/homeharbor/internal/control/policy"
)

func (s *Server) latestPolicy(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.policy.Latest(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load policy")
		return
	}

	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) replacePolicy(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Rules []policy.Rule `json:"rules"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	snapshot, err := s.policy.Replace(r.Context(), input.Rules)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_policy", "policy rules are invalid")
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}
