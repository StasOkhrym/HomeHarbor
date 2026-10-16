package node

import (
	"context"
	"errors"

	"github.com/StasOkhrym/homeharbor/internal/node"
	nodepath "github.com/StasOkhrym/homeharbor/internal/node/path"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

// The app retains this owner until all transports have joined. A control
// reconnect cannot close networking or manufacture a new runtime identity.
type coordinationRuntime struct {
	worker     lifecycle.Component
	connection node.CoordinationConfig
	cleanup    func(context.Context) error
}

func (r *coordinationRuntime) Run(ctx context.Context) error { return r.worker.Run(ctx) }
func (r *coordinationRuntime) Close(ctx context.Context, previous error) error {
	var cleanupErr error
	if r.cleanup != nil {
		cleanupErr = r.cleanup(ctx)
	}

	if r.connection.Telemetry != nil {
		if errors.Join(previous, cleanupErr) != nil {
			r.connection.Telemetry.Failed()
		} else {
			r.connection.Telemetry.Stopped()
		}

		// Reporting is optional. A control outage must not fail successful cleanup;
		// without receipt, the last observation naturally becomes stale/unknown.
		_ = node.ReportRuntimeShutdown(ctx, r.connection)
	}

	return cleanupErr
}

func prepareRuntimeTelemetry(
	role Role,
	cfg config.Node,
	state node.State,
	paths *nodepath.PathSelector,
) (*node.RuntimeTelemetry, error) {
	telemetry := node.TelemetryConfig{
		DeviceID:     state.DeviceID,
		Role:         "client",
		PathDeviceID: cfg.Relay.DestinationDevice,
	}
	if role == Gateway {
		telemetry.Role = "gateway"
	}

	if !cfg.Native.Enabled {
		statistics, err := node.NewWireGuardStatistics(cfg.WireGuard.InterfaceName, nil)
		if err == nil {
			telemetry.Statistics = statistics
		}
	}

	if paths != nil {
		telemetry.SelectedPath = paths.Current
		telemetry.PathChanges = paths.Changes
	}

	return node.NewRuntimeTelemetry(telemetry)
}
