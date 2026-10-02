package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

func TestPostgresIndependentNetworksOwnTheirGenesisRevision(t *testing.T) {
	pool := snapshotTestPool(t)

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	repo := New(pool)
	for _, network := range []string{"home", "staging"} {
		envelope, err := snapshot.Sign(
			snapshot.NetworkSnapshot{NetworkID: network, Revision: 1},
			key,
			"root",
		)
		if err != nil {
			t.Fatal(err)
		}

		if err := repo.Append(context.Background(), network, 0, nil, envelope); err != nil {
			t.Fatalf("network %s genesis: %v", network, err)
		}
	}
}
