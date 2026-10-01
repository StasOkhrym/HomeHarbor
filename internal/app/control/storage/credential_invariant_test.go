package storage_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/app/control/workflows"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

func TestPostgresMigrationRefusesDuplicatesWithoutDeletingCredentialHistory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.activation.ApproveSigned(ctx, f.approval); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `DROP INDEX device_credentials_one_active_per_device`); err != nil {
		t.Fatal(err)
	}
	for i := byte(1); i <= 2; i++ {
		hash := [32]byte{i}
		if _, err := f.pool.Exec(
			ctx,
			`INSERT INTO device_credentials(device_id,credential_hash,expires_at) VALUES('linux',$1,$2)`,
			hash[:],
			time.Now().Add(time.Minute),
		); err != nil {
			t.Fatal(err)
		}
	}
	sql, err := os.ReadFile("../../../../migrations/000011_active_device_credential.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, string(sql)); err == nil {
		t.Fatal("multiple active credentials permitted")
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM device_credentials WHERE revoked_at IS NULL`).
		Scan(&count); err != nil ||
		count != 2 {
		t.Fatalf("migration changed history: count=%d err=%v", count, err)
	}
}

func TestPostgresConcurrentApprovalProducesOneDeviceAndOneEventPair(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		group.Add(1)
		go func() { defer group.Done(); _, err := f.activation.ApproveSigned(ctx, f.approval); failures <- err }()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Error(err)
		}
	}
	for table, want := range map[string]int{"devices": 1, "access_profile_devices": 1, "event_outbox": 2, "device_credentials": 0} {
		var count int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != want {
			t.Fatalf("%s rows=%d want=%d err=%v", table, count, want, err)
		}
	}
}

func TestPostgresSharedChallengeIsConsumedOnceConcurrently(t *testing.T) {
	if os.Getenv("TEST_REDIS_URL") == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.activation.ApproveSigned(ctx, f.approval); err != nil {
		t.Fatal(err)
	}
	f.publish(t)
	c, err := f.activation.Challenge(ctx, f.record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := workflows.SignClaim(c, f.deviceKey)
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := f.activation.Claim(ctx, f.record.InviteID, proof)
			failures <- err
		}()
	}
	group.Wait()
	close(failures)
	successes := 0
	for err := range failures {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("same nonce succeeded %d times", successes)
	}
}

func TestPostgresClaimRotationAndRevocationUseConsistentLockOrder(t *testing.T) {
	if os.Getenv("TEST_REDIS_URL") == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := f.activation.ApproveSigned(ctx, f.approval); err != nil {
		t.Fatal(err)
	}
	f.publish(t)
	first := f.claim(t)
	c, err := f.activation.Challenge(ctx, f.record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := workflows.SignClaim(c, f.deviceKey)
	var group sync.WaitGroup
	results := make(chan error, 3)
	start := make(chan struct{})
	operations := []func() error{
		func() error { _, err := f.activation.Claim(ctx, f.record.InviteID, proof); return err },
		func() error {
			return f.devices.RotateCredential(
				ctx,
				"linux",
				sha256.Sum256([]byte(first.Device.Credential)),
				[32]byte{9},
				time.Now(),
				time.Now().Add(time.Minute),
			)
		},
		func() error { return f.devices.RevokeDevice(ctx, "linux", time.Now()) },
	}
	for _, op := range operations {
		group.Add(1)
		go func() { defer group.Done(); <-start; results <- op() }()
	}
	close(start)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, devices.ErrDeviceNotFound) {
			t.Errorf("claim/rotate/revoke failed: %v", err)
		}
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM device_credentials WHERE revoked_at IS NULL`).
		Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("revoked device has %d active credentials err=%v", count, err)
	}
}
