package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestCompanionRequestBindsMethodPathAndNonce(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignCompanionRequest("GET", "/api/v1/coordination/snapshot/companion", "nonce-1", "root-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCompanionRequest("GET", "/api/v1/coordination/snapshot/companion", "nonce-1", "root-1", signature, publicKey); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		method string
		path   string
		nonce  string
	}{
		{method: "POST", path: "/api/v1/coordination/snapshot/companion", nonce: "nonce-1"},
		{method: "GET", path: "/api/v1/coordination/snapshot", nonce: "nonce-1"},
		{method: "GET", path: "/api/v1/coordination/snapshot/companion", nonce: "nonce-2"},
	} {
		if err := VerifyCompanionRequest(invalid.method, invalid.path, invalid.nonce, "root-1", signature, publicKey); !errors.Is(err, ErrInvalidCompanionRequest) {
			t.Fatalf("invalid request %#v error=%v", invalid, err)
		}
	}
}
