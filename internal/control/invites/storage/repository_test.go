package storage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/invites"
	"github.com/sokhrym/go-tunnels/internal/invite"
	"github.com/sokhrym/go-tunnels/migrations"
)

func TestPostgresInviteBlocksAfterFiveInvalidCodes(t *testing.T) {
	pool := invitesTestPool(t)
	store := New(pool)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	profileID := uniqueInviteIntegrationID()
	if _, err := pool.Exec(
		context.Background(),
		`INSERT INTO access_profiles(id,name,created_at) VALUES($1,$2,$3)`,
		profileID,
		profileID,
		now,
	); err != nil {
		t.Fatal(err)
	}
	local, err := invite.New("home", profileID, time.Hour, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := invite.SignPermit(local.Permit, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	_, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := local.Proof(uniqueInviteIntegrationID(), devicePrivate, local.Code, bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := invites.NewService(store, rootPublic, "home", func() time.Time { return now })
	if err := service.SubmitProof(context.Background(), permit, proof); err != nil {
		t.Fatal(err)
	}
	wrongCode := "00000000"
	if wrongCode == local.Code {
		wrongCode = "00000001"
	}
	for range 4 {
		if _, err := service.Approve(
			context.Background(),
			local.Permit.InviteID,
			wrongCode,
		); !errors.Is(
			err,
			invites.ErrInvalidCode,
		) {
			t.Fatalf("invalid code error=%v, want ErrInvalidCode", err)
		}
	}
	if _, err := service.Approve(
		context.Background(),
		local.Permit.InviteID,
		wrongCode,
	); !errors.Is(
		err,
		invites.ErrInviteBlocked,
	) {
		t.Fatalf("fifth invalid code error=%v, want ErrInviteBlocked", err)
	}
	record, err := service.Get(context.Background(), local.Permit.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != invites.StatusBlocked || record.FailedCodeAttempts != invites.MaxInvalidCodeAttempts ||
		record.BlockedAt == nil {
		t.Fatalf("lockout record=%#v", record)
	}
}

func invitesTestPool(t *testing.T) *pgxpool.Pool {
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

func uniqueInviteIntegrationID() string {
	return fmt.Sprintf("go-tunnels-invite-%d", time.Now().UnixNano())
}
