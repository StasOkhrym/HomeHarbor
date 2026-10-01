package snapshots

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

func TestPublishEnforcesSequentialSignedSnapshots(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(NewMemoryStore(), publicKey, "home")
	first, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Publish(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Latest(context.Background()); err != nil {
		t.Fatal(err)
	}
	gap, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 3},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Publish(context.Background(), gap); !errors.Is(err, snapshot.ErrRevisionGap) {
		t.Fatalf("gap publish error = %v", err)
	}
}
