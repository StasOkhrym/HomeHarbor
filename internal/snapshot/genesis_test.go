package snapshot

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestVerifyNextRequiresRevisionOneGenesis(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []uint64{2, 7} {
		envelope, err := Sign(NetworkSnapshot{NetworkID: "home", Revision: revision}, private, "root")
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyNext(envelope, public, "home", 0, nil); !errors.Is(err, ErrRevisionGap) {
			t.Fatalf("revision %d accepted as genesis: %v", revision, err)
		}
	}
}
