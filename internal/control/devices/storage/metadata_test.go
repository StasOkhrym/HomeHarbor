package storage_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	devicesstorage "github.com/StasOkhrym/homeharbor/internal/control/devices/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/events"
	workflowstorage "github.com/StasOkhrym/homeharbor/internal/control/transactions"
)

func TestPostgresDeviceMetadataAndHistoricSnapshot(t *testing.T) {
	pool := devicesTestPool(t)
	store := devicesstorage.New(pool, workflowstorage.AppendEvent)
	service := devices.NewService(store, time.Now, nil)

	token, err := service.IssueEnrollmentToken(t.Context(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	identity, wg := validPostgresPublicKeys(t)

	d, err := service.Enroll(
		t.Context(),
		devices.EnrollRequest{
			Token:              token.Token,
			Name:               "First name",
			IdentityPublicKey:  identity,
			WireGuardPublicKey: wg,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	metadata := devices.NewMetadataService(store)
	report := devices.Metadata{
		Name:          "Kitchen Mac",
		Platform:      "macos",
		OSVersion:     "15.0",
		ClientVersion: "0.1.0",
	}

	if err := metadata.Report(t.Context(), d.ID, report); err != nil {
		t.Fatal(err)
	}

	actor := audit.WithContext(
		t.Context(),
		audit.Context{
			ActorType: "admin",
			ActorID:   "account-1",
			ActorName: "Olena",
			SourceIP:  "192.0.2.10",
		},
	)

	if err := service.Revoke(actor, d.ID); err != nil {
		t.Fatal(err)
	}

	// Change the current name after the event but before asynchronous projection.
	if _, err := pool.Exec(
		t.Context(),
		`UPDATE devices SET name='Later name' WHERE id=$1`,
		d.ID,
	); err != nil {
		t.Fatal(err)
	}

	var data []byte

	if err := pool.QueryRow(t.Context(), `SELECT payload FROM event_outbox WHERE topic='device.revoked' AND payload->>'aggregate_id'=$1 ORDER BY id DESC LIMIT 1`, d.ID).
		Scan(&data); err != nil {
		t.Fatal(err)
	}

	fact, err := events.Decode(1, data)
	if err != nil {
		t.Fatal(err)
	}

	event := fact.AuditEvent()

	if event.ActorID != "account-1" || event.Metadata["target_name"] != "Kitchen Mac" ||
		event.Metadata["device_platform"] != "macos" ||
		event.Metadata["outcome"] != "success" {
		t.Fatalf("historic context not captured: %s", data)
	}

	if err := metadata.Report(
		t.Context(),
		d.ID,
		report,
	); !errors.Is(
		err,
		devices.ErrDeviceNotFound,
	) {
		t.Fatalf("revoked device metadata accepted: %v", err)
	}

	for _, bad := range []devices.Metadata{{Name: " bad", Platform: "macos"}, {Name: "Valid", Platform: "SECRET_PLATFORM"}, {Name: "Valid", Platform: "ios", OSVersion: "bad\nversion"}} {
		if err := metadata.Report(
			t.Context(),
			d.ID,
			bad,
		); !errors.Is(
			err,
			devices.ErrInvalidMetadata,
		) {
			value, _ := json.Marshal(bad)

			t.Fatalf("invalid metadata %s: %v", value, err)
		}
	}
}
