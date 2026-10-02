package storage_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	workflowstorage "github.com/StasOkhrym/homeharbor/internal/app/control/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	devicesstorage "github.com/StasOkhrym/homeharbor/internal/control/devices/storage"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func TestPostgresEnrollmentWritesDeviceAndOutboxAtomically(t *testing.T) {
	pool := devicesTestPool(t)
	store := devicesstorage.New(pool, workflowstorage.AppendEvent)
	service := devices.NewService(store, time.Now, nil)

	label := uniqueIntegrationLabel()

	token, err := service.IssueEnrollmentToken(context.Background(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	identityPublicKey, wireGuardPublicKey := validPostgresPublicKeys(t)

	device, err := service.Enroll(context.Background(), devices.EnrollRequest{
		Token:              token.Token,
		Name:               label,
		IdentityPublicKey:  identityPublicKey,
		WireGuardPublicKey: wireGuardPublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	var topic string
	var payload []byte

	if err := pool.QueryRow(context.Background(), `SELECT topic,payload FROM event_outbox WHERE topic='device.enrolled' AND payload->>'aggregate_id'=$1 ORDER BY id DESC LIMIT 1`, device.ID).
		Scan(&topic, &payload); err != nil {
		t.Fatal(err)
	}

	var event devices.Event

	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}

	if topic != "device.enrolled" || event.AggregateID != device.ID {
		t.Fatalf("outbox event = %#v, topic=%q", event, topic)
	}
}

func TestPostgresEnrollmentTokenIsConsumedOnceConcurrently(t *testing.T) {
	pool := devicesTestPool(t)
	store := devicesstorage.New(pool, workflowstorage.AppendEvent)
	service := devices.NewService(store, time.Now, nil)

	token, err := service.IssueEnrollmentToken(context.Background(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	label := uniqueIntegrationLabel()

	var group sync.WaitGroup
	results := make(chan error, 2)
	for index := range 2 {
		group.Add(1)
		go func(index int) {
			defer group.Done()

			identityPublicKey, wireGuardPublicKey := validPostgresPublicKeys(t)

			_, enrollErr := service.Enroll(context.Background(), devices.EnrollRequest{
				Token:              token.Token,
				Name:               label,
				IdentityPublicKey:  identityPublicKey,
				WireGuardPublicKey: wireGuardPublicKey,
			})
			results <- enrollErr
		}(index)
	}

	group.Wait()
	close(results)

	successes := 0
	for enrollErr := range results {
		if enrollErr == nil {
			successes++
		}
	}

	if successes != 1 {
		t.Fatalf("successful enrollments = %d, want 1", successes)
	}
}

func devicesTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(pool.Close)

	if err := migrations.Up(context.Background(), pool); err != nil {
		t.Fatal(err)
	}

	return pool
}

func uniqueIntegrationLabel() string {
	return fmt.Sprintf("homeharbor-integration-%d", time.Now().UnixNano())
}

func validPostgresPublicKeys(t *testing.T) (identity, wireGuard string) {
	t.Helper()

	_, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	wireGuardPrivate, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	return base64.RawURLEncoding.EncodeToString(
			identityPrivate.Public().(ed25519.PublicKey),
		), wireGuardPrivate.PublicKey().
			String()
}
