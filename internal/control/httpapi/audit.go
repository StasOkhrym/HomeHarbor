package httpapi

import (
	"net/http"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

const (
	defaultAuditLimit = 50
	maxAuditLimit     = audit.MaxQueryLimit
)

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		writeError(w, http.StatusNotFound, "audit is unavailable")
		return
	}

	query, err := audit.ParseQuery(r.URL.Query(), time.Now(), defaultAuditLimit)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_filter", err.Error())
		return
	}

	records, err := s.audit.ListRecords(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list audit events")
		return
	}

	entries := make([]audit.Event, 0, len(records))
	for _, record := range records {
		entries = append(entries, audit.PublicEvent(record.Event))
	}

	writeJSON(w, http.StatusOK, map[string]any{"events": entries})
}
