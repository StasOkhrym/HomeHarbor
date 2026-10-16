package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/telemetry"
)

type TelemetryReader interface {
	Latest(context.Context, int) ([]telemetry.Observation, error)
}

func (s *Server) listConnections(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "choose a positive report limit")
			return
		}

		limit = min(parsed, 1000)
	}

	observations, err := s.telemetry.Latest(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "runtime reports unavailable")
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"observations":        observations,
			"server_time":         time.Now().UTC(),
			"stale_after_seconds": int(telemetry.StaleAfter.Seconds()),
		},
	)
}
