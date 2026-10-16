package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
)

type DeviceMetadataWriter interface {
	Report(context.Context, string, devices.Metadata) error
}

func (s *Server) reportDeviceMetadata(w http.ResponseWriter, r *http.Request) {
	device, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "device authentication required")
		return
	}

	var value devices.Metadata
	if !decodeJSON(w, r, &value) {
		return
	}

	if err := s.deviceMetadata.Report(r.Context(), device.ID, value); err != nil {
		switch {
		case errors.Is(err, devices.ErrInvalidMetadata):
			writeError(w, http.StatusBadRequest, "invalid device metadata")
		case errors.Is(err, devices.ErrDeviceNotFound):
			writeError(w, http.StatusUnauthorized, "device authentication required")
		default:
			writeError(w, http.StatusServiceUnavailable, "device metadata unavailable")
		}

		return
	}

	w.WriteHeader(http.StatusNoContent)
}
