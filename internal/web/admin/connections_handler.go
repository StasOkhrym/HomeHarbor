package admin

import (
	"net/http"
	"time"
)

func (h *Handler) loadConnections(r *http.Request, model *Page) int {
	h.loadDevices(r.Context(), model)
	if !model.Devices.Ready {
		model.Connections.Error = "Device names could not be loaded"
		return http.StatusServiceUnavailable
	}

	var status int
	model.Connections, status = LoadConnections(
		r.Context(),
		h.telemetry,
		model.Devices.Items,
		r.URL.Query(),
		time.Now,
	)

	return status
}

func (h *Handler) connectionsFragment(w http.ResponseWriter, r *http.Request) {
	model := NewPage("connections", "", "")
	status := h.loadConnections(r, &model)
	RenderFragment(w, status, "connections-feed", model, h.logger)
}
