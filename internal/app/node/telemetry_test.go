package node

import (
	"context"
	"errors"
	"testing"

	runtimenode "github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func TestCoordinationRuntimeMarksStoppedOnlyAfterOwnedCleanup(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "stopped", true: "failed"}[fail], func(t *testing.T) {
			source, err := runtimenode.NewRuntimeTelemetry(
				runtimenode.TelemetryConfig{DeviceID: "client", Role: "client"},
			)
			if err != nil {
				t.Fatal(err)
			}

			cleanupErr := errors.New("owned cleanup failed")
			owner := &coordinationRuntime{
				connection: runtimenode.CoordinationConfig{DeviceID: "client", Telemetry: source},
				cleanup: func(ctx context.Context) error {
					if ctx.Err() != nil {
						t.Fatal("cleanup reused cancelled worker context")
					}

					report, _ := source.Snapshot(ctx)

					if report.State == protocol.RuntimeStopped {
						t.Fatal("stopped before cleanup")
					}

					if fail {
						return cleanupErr
					}

					return nil
				},
			}

			err = owner.Close(context.Background(), nil)

			if fail && !errors.Is(err, cleanupErr) {
				t.Fatalf("cleanup failure lost: %v", err)
			}
			if !fail && err != nil {
				t.Fatal(err)
			}

			report, _ := source.Snapshot(t.Context())
			want := protocol.RuntimeStopped
			if fail {
				want = protocol.RuntimeFailed
			}

			if report.State != want {
				t.Fatalf("cleanup status %s, want %s", report.State, want)
			}
		})
	}
}

func TestOptionalStatisticsCannotRejectOtherwiseSupportedInterface(t *testing.T) {
	cfg := config.Node{}
	cfg.WireGuard.InterfaceName = "0wg0" // Accepted by the existing network owner.

	source, err := prepareRuntimeTelemetry(Client, cfg, runtimenode.State{DeviceID: "client"}, nil)
	if err != nil {
		t.Fatalf("optional statistics blocked VPN startup: %v", err)
	}

	report, err := source.Snapshot(t.Context())

	if err != nil || report.State != protocol.RuntimeStarting ||
		report.Observations[0].CountersAvailable {
		t.Fatalf("unavailable statistics invented data: %+v %v", report, err)
	}
}
