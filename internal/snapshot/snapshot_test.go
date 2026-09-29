package snapshot

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestSignVerifyAndAcceptNextSnapshot(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(NetworkSnapshot{NetworkID: "home", Revision: 1, Services: []Service{{ID: "cloud", Name: "Nextcloud", Kind: "web", URL: "https://cloud.home.example.com"}}}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyNext(signed, publicKey, "home", 0, nil); err != nil {
		t.Fatal(err)
	}
	if len(signed.Payload) == 0 || len(signed.Hash) != 32 || len(signed.Signature) != ed25519.SignatureSize {
		t.Fatalf("signed envelope = %#v", signed)
	}

	next, err := Sign(NetworkSnapshot{NetworkID: "home", Revision: 2, PreviousHash: signed.Hash, Services: []Service{{ID: "cloud", Name: "Nextcloud", Kind: "web", URL: "https://cloud.home.example.com"}}}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyNext(next, publicKey, "home", 1, signed.Hash); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTamperingRollbackAndGap(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(NetworkSnapshot{NetworkID: "home", Revision: 1}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	tampered := signed
	tampered.Payload = append([]byte(nil), signed.Payload...)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if err = VerifyNext(tampered, publicKey, "home", 0, nil); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("tampered error = %v", err)
	}
	if err = VerifyNext(signed, publicKey, "home", 1, signed.Hash); !errors.Is(err, ErrRevisionRollback) {
		t.Fatalf("rollback error = %v", err)
	}
	gap, err := Sign(NetworkSnapshot{NetworkID: "home", Revision: 3, PreviousHash: signed.Hash}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyNext(gap, publicKey, "home", 1, signed.Hash); !errors.Is(err, ErrRevisionGap) {
		t.Fatalf("gap error = %v", err)
	}
}

func TestSignRejectsInvalidService(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Sign(NetworkSnapshot{NetworkID: "home", Revision: 1, Services: []Service{{ID: "cloud", URL: "http://cloud.home"}}}, privateKey, "root-1"); err == nil {
		t.Fatal("insecure service URL accepted")
	}
}
