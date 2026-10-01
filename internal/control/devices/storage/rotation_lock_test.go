package storage_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	workflowstorage "github.com/sokhrym/go-tunnels/internal/app/control/storage"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	devicesstorage "github.com/sokhrym/go-tunnels/internal/control/devices/storage"
)

func TestPostgresRotationLocksDeviceBeforeCredential(t *testing.T) {
	pool := devicesTestPool(t)
	service := devices.NewService(devicesstorage.New(pool, workflowstorage.AppendEvent), time.Now, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	token, err := service.IssueEnrollmentToken(ctx, devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ipk, wpk := validPostgresPublicKeys(t)
	d, err := service.Enroll(
		ctx,
		devices.EnrollRequest{
			Token:              token.Token,
			Name:               uniqueIntegrationLabel(),
			IdentityPublicKey:  ipk,
			WireGuardPublicKey: wpk,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	rotationConfig := pool.Config()
	rotationConfig.MaxConns = 1
	rotationPool, err := pgxpool.NewWithConfig(ctx, rotationConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer rotationPool.Close()
	var pid int
	if err := rotationPool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	claim, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = claim.Rollback(context.Background()) }()
	if _, err := claim.Exec(ctx, `SELECT id FROM devices WHERE id=$1 FOR UPDATE`, d.ID); err != nil {
		t.Fatal(err)
	}
	rotationDone := make(chan error, 1)
	go func() {
		now := time.Now()
		rotationDone <- devicesstorage.New(rotationPool, workflowstorage.AppendEvent).RotateCredential(ctx, d.ID, sha256.Sum256([]byte(d.Credential)), sha256.Sum256([]byte("replacement-"+d.ID)), now, now.Add(time.Hour))
	}()
	defer func() {
		_ = claim.Rollback(context.Background())
		if err := <-rotationDone; err != nil {
			t.Errorf("rotation after claim rollback: %v", err)
		}
	}()
	// Wait for the competing transaction to block, not for a guessed delay.
	// A claim owns the device row first; rotation must wait there without
	// taking a credential lock that the claim will need next.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).
			Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("rotation never reached the lock boundary")
		case <-ticker.C:
		}
	}
	if _, err := claim.Exec(
		ctx,
		`SELECT device_id FROM device_credentials WHERE device_id=$1 AND revoked_at IS NULL FOR UPDATE NOWAIT`,
		d.ID,
	); err != nil {
		t.Fatalf("rotation acquired a credential lock before the device: %v", err)
	}
}
