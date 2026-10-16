package node

import (
	"context"
	"encoding/json"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type RuntimeTelemetrySource interface {
	Snapshot(context.Context) (protocol.TelemetryReport, error)
	Changes() <-chan struct{}
	PathChanges() <-chan struct{}
}

// runTelemetryPublisher belongs to one coordination session. The caller joins
// it before reconnecting; generation/sequence never outlive that connection.
func runTelemetryPublisher(
	ctx context.Context,
	generation uint64,
	source RuntimeTelemetrySource,
	ticks <-chan time.Time,
	write func(any) error,
) {
	var sequence uint64
	for {
		changes, pathChanges := source.Changes(), source.PathChanges()
		if ctx.Err() != nil {
			return
		}

		operation, cancel := context.WithTimeout(ctx, 5*time.Second)
		report, err := source.Snapshot(operation)
		cancel()
		if ctx.Err() != nil {
			return
		}

		if err == nil {
			sequence++
			report.Generation, report.Sequence = generation, sequence
			if report.Validate() == nil {
				payload, err := json.Marshal(report)
				if err == nil &&
					write(protocol.Message{Type: "telemetry.report", Payload: payload}) != nil {
					return
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticks:
		case <-changes:
		case <-pathChanges:
		}
	}
}
