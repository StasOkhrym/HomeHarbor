package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

func TestTelemetryTracksActualApplyWithoutChangingNativeRestoreAuthority(t *testing.T) {
	value, _, _ := telemetryTopology(t)
	value.Revision = 1

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := snapshot.Sign(value, private, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	for _, native := range []bool{false, true} {
		t.Run(map[bool]string{false: "kernel", true: "native"}[native], func(t *testing.T) {
			source, err := NewRuntimeTelemetry(
				TelemetryConfig{DeviceID: "gateway", Role: "gateway"},
			)
			if err != nil {
				t.Fatal(err)
			}

			cfg := CoordinationConfig{
				NetworkID:     value.NetworkID,
				RootPublicKey: public,
				StatePath:     filepath.Join(t.TempDir(), "head.json"),
				Telemetry:     source,
			}

			prepared, err := prepareSnapshotState(cfg.StatePath, envelope)
			if err != nil {
				t.Fatal(err)
			}

			if err := prepared.commit(); err != nil {
				t.Fatal(err)
			}

			var applier SnapshotApplier = &stateApplier{}
			owner := &deferredStateApplier{}
			if native {
				applier = owner
			}

			cursor, err := restoreSnapshotCursor(t.Context(), cfg, applier)
			if err != nil {
				t.Fatal(err)
			}

			report, err := source.Snapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if native {
				if report.State != protocol.RuntimeStarting || report.AppliedRevision != 0 {
					t.Fatal("checkpoint verification invented applied native state")
				}

				owner.fail = errors.New("owned apply failure")

				if reconcileSnapshotHead(t.Context(), cfg, applier, &cursor, envelope) == nil {
					t.Fatal("missing host error")
				}

				failed, _ := source.Snapshot(t.Context())

				if failed.State != protocol.RuntimeFailed || failed.AppliedRevision != 0 {
					t.Fatalf("failed apply accepted revision: %+v", failed)
				}

				owner.fail = nil

				if err := reconcileSnapshotHead(
					t.Context(),
					cfg,
					applier,
					&cursor,
					envelope,
				); err != nil {
					t.Fatal(err)
				}

				if len(owner.applied) != 1 {
					t.Fatal("native signed apply was lost or duplicated")
				}
			}

			report, err = source.Snapshot(context.Background())

			if err != nil || report.State != protocol.RuntimeRunning ||
				report.AppliedRevision != 1 {
				t.Fatalf("actual owner apply not observed: %+v %v", report, err)
			}

			original := report.RuntimeID

			if err := reconcileSnapshotHead(
				t.Context(),
				cfg,
				applier,
				&cursor,
				envelope,
			); err != nil {
				t.Fatal(err)
			}

			report, _ = source.Snapshot(t.Context())

			if report.RuntimeID != original {
				t.Fatal("matching head restarted runtime")
			}
		})
	}
}
