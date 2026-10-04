package storage_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	workflowstorage "github.com/StasOkhrym/homeharbor/internal/app/control/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	devicesstorage "github.com/StasOkhrym/homeharbor/internal/control/devices/storage"
)

func TestPostgresRecoveredCredentialInvalidatesOldCredential(t *testing.T) {
	pool := devicesTestPool(t)
	store := devicesstorage.New(pool, workflowstorage.AppendEvent)
	svc := devices.NewService(store, time.Now, nil)
	ctx := t.Context()

	token, err := svc.IssueEnrollmentToken(ctx, devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	identity, wg := validPostgresPublicKeys(t)

	d, err := svc.Enroll(
		ctx,
		devices.EnrollRequest{
			Token:              token.Token,
			Name:               uniqueIntegrationLabel(),
			IdentityPublicKey:  identity,
			WireGuardPublicKey: wg,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Failed outbox publication must restore the original credential.
	broken := devices.NewService(
		devicesstorage.New(
			pool,
			func(context.Context, pgx.Tx, devices.Event) error { return errors.New("injected outbox failure") },
		),
		time.Now,
		nil,
	)

	if _, err := broken.RecoverCredential(ctx, d.ID, identity); err == nil {
		t.Fatal("outbox failure committed")
	}

	if _, err := svc.Authenticate(ctx, d.Credential); err != nil {
		t.Fatal("rollback invalidated old credential")
	}

	if _, err := svc.RecoverCredential(
		ctx,
		d.ID,
		"wrong-identity",
	); !errors.Is(
		err,
		devices.ErrDeviceNotFound,
	) {
		t.Fatalf("wrong identity accepted: %v", err)
	}

	lease, err := svc.RecoverCredential(ctx, d.ID, identity)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Authenticate(ctx, d.Credential); !errors.Is(err, devices.ErrDeviceNotFound) {
		t.Fatal("old credential remained usable")
	}

	if _, err := svc.Authenticate(ctx, lease.Credential); err != nil {
		t.Fatal(err)
	}

	var expiry time.Time

	hash := sha256.Sum256([]byte(lease.Credential))

	if err := pool.QueryRow(ctx, `SELECT expires_at FROM device_credentials WHERE credential_hash=$1`, hash[:]).
		Scan(&expiry); err != nil {
		t.Fatal(err)
	}

	if expiry.Sub(lease.ExpiresAt).Abs() > time.Microsecond {
		t.Fatal("lease did not reflect committed issuance expiry")
	}

	var count int

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM event_outbox WHERE topic='device.credential_recovered' AND payload->>'aggregate_id'=$1`, d.ID).
		Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count != 1 {
		t.Fatalf("outbox facts=%d", count)
	}

	if err := svc.Revoke(ctx, d.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.RecoverCredential(
		ctx,
		d.ID,
		identity,
	); !errors.Is(
		err,
		devices.ErrDeviceNotFound,
	) {
		t.Fatal("revoked device recovered")
	}
}

func TestPostgresRecoveryRechecksRevocationUnderDeviceLock(t *testing.T) {
	pool := devicesTestPool(t)
	store := devicesstorage.New(pool, workflowstorage.AppendEvent)
	svc := devices.NewService(store, time.Now, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	token, err := svc.IssueEnrollmentToken(ctx, devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	identity, wg := validPostgresPublicKeys(t)

	d, err := svc.Enroll(
		ctx,
		devices.EnrollRequest{
			Token:              token.Token,
			Name:               uniqueIntegrationLabel(),
			IdentityPublicKey:  identity,
			WireGuardPublicKey: wg,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// The workflow's pre-read can observe active while revocation owns the row.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err = tx.Exec(
		ctx,
		`UPDATE devices SET status='revoked',revoked_at=$2 WHERE id=$1`,
		d.ID,
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { _, err := svc.RecoverCredential(ctx, d.ID, identity); done <- err }()
	// Observe a lock wait rather than relying on scheduling or a fixed sleep.
	for {
		var waits int

		err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%SELECT identity_public_key FROM devices%'`).
			Scan(&waits)
		if err != nil {
			t.Fatal(err)
		}

		if waits > 0 {
			break
		}

		select {
		case <-ctx.Done():
			t.Fatal("recovery did not wait on device lock")
		case <-time.After(time.Millisecond):
		}
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if err := <-done; !errors.Is(err, devices.ErrDeviceNotFound) {
		t.Fatalf("stale active read authorized replacement: %v", err)
	}

	var count int

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM event_outbox WHERE topic='device.credential_recovered' AND payload->>'aggregate_id'=$1`, d.ID).
		Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatal("revoked recovery committed fact")
	}
}

func TestPostgresRotatedCredentialAuthenticatesWithIssuanceExpiry(t *testing.T) {
	pool := devicesTestPool(t)

	now := time.Now().UTC()
	svc := devices.NewService(
		devicesstorage.New(pool, workflowstorage.AppendEvent),
		func() time.Time { return now },
		nil,
	)

	token, err := svc.IssueEnrollmentToken(t.Context(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	identity, wg := validPostgresPublicKeys(t)

	d, err := svc.Enroll(
		t.Context(),
		devices.EnrollRequest{
			Token:              token.Token,
			Name:               uniqueIntegrationLabel(),
			IdentityPublicKey:  identity,
			WireGuardPublicKey: wg,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(5 * time.Minute)

	lease, err := svc.RotateCredential(t.Context(), d.ID, d.Credential)
	if err != nil {
		t.Fatal(err)
	}

	admitted, err := svc.Authenticate(t.Context(), lease.Credential)
	if err != nil {
		t.Fatal(err)
	}

	if admitted.CredentialExpiresAt.Sub(lease.ExpiresAt).Abs() > time.Microsecond {
		t.Fatal("authenticated expiry did not follow rotated lease")
	}
}
