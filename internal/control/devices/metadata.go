package devices

import (
	"context"
	"errors"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

// Metadata is self-reported display information. It cannot change keys, role,
// signed topology, routes or any authorization decision.
type Metadata struct {
	Name          string `json:"name"`
	Platform      string `json:"platform"`
	OSVersion     string `json:"os_version,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

var ErrInvalidMetadata = errors.New("invalid device metadata")

type MetadataRepository interface {
	UpdateMetadata(context.Context, string, Metadata) error
}
type MetadataService struct{ store MetadataRepository }

func NewMetadataService(store MetadataRepository) *MetadataService {
	return &MetadataService{store: store}
}

func (s *MetadataService) Report(ctx context.Context, id string, value Metadata) error {
	if !audit.PublicText(value.Name, maxDeviceNameBytes) || !audit.Platform(value.Platform) ||
		value.OSVersion != "" && !audit.PublicText(value.OSVersion, 64) ||
		value.ClientVersion != "" && !audit.PublicText(value.ClientVersion, 64) {
		return ErrInvalidMetadata
	}

	return s.store.UpdateMetadata(ctx, id, value)
}
