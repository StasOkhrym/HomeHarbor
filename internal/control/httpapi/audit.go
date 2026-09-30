package httpapi

import (
	"net/http"
	"strconv"
	"strings"
)

const (
	defaultAuditLimit = 50
	maxAuditLimit     = 200
)

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		writeError(w, http.StatusNotFound, "audit is unavailable")
		return
	}
	limit := defaultAuditLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			writeErrorCode(w, http.StatusBadRequest, "invalid_limit", "audit limit must be a positive integer")
			return
		}
		limit = parsed
		if limit > maxAuditLimit {
			limit = maxAuditLimit
		}
	}
	entries, err := s.audit.List(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list audit events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": entries})
}
