package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCredentialRecoveryCanonicalVector(t *testing.T) {
	raw, err := os.ReadFile("../../api/testdata/credential-recovery.json")
	if err != nil {
		t.Fatal(err)
	}

	var vector struct {
		Challenge CredentialChallenge `json:"challenge"`
		Seed      string              `json:"seed_hex"`
		Signing   string              `json:"signing_hex"`
		Signature string              `json:"signature"`
	}

	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}

	seed, err := hex.DecodeString(vector.Seed)
	if err != nil {
		t.Fatal(err)
	}

	key := ed25519.NewKeyFromSeed(seed)

	proof, err := SignCredentialProof(vector.Challenge, key)
	if err != nil {
		t.Fatal(err)
	}

	b, _ := vector.Challenge.SigningBytes()

	if hex.EncodeToString(b) != vector.Signing || proof.Signature != vector.Signature {
		t.Fatal("canonical recovery vector changed")
	}
	if !bytes.HasPrefix(b, []byte("homeharbor/credential-recovery/v1\x00")) {
		t.Fatal("wrong signing domain")
	}
	if VerifyCredentialProof(proof, key.Public().(ed25519.PublicKey)) != nil {
		t.Fatal("vector signature rejected")
	}
}

func TestCredentialProofBindsEveryField(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	c := CredentialChallenge{
		Version:   1,
		NetworkID: "network",
		DeviceID:  "device",
		Nonce:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		ExpiresAt: 1800000060,
	}

	proof, _ := SignCredentialProof(c, key)
	for _, change := range []func(*CredentialChallenge){func(c *CredentialChallenge) { c.Version++ }, func(c *CredentialChallenge) { c.NetworkID += "x" }, func(c *CredentialChallenge) { c.DeviceID += "x" }, func(c *CredentialChallenge) {
		c.Nonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	}, func(c *CredentialChallenge) { c.ExpiresAt++ }} {
		p := proof

		change(&p.Challenge)

		if VerifyCredentialProof(p, key.Public().(ed25519.PublicKey)) == nil {
			t.Fatal("changed signed field accepted")
		}
	}

	proof.Signature += "="

	if VerifyCredentialProof(proof, key.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("padded signature accepted")
	}
}

func TestCredentialProofRejectsNonCanonicalBase64(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	challenge := CredentialChallenge{
		Version:   1,
		NetworkID: "network",
		DeviceID:  "device",
		Nonce:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		ExpiresAt: 1800000060,
	}

	proof, _ := SignCredentialProof(challenge, key)
	proof.Signature = "\n" + proof.Signature

	if VerifyCredentialProof(proof, key.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("newline in signature accepted")
	}

	challenge.Nonce = "\n" + challenge.Nonce

	if _, err := challenge.SigningBytes(); err == nil {
		t.Fatal("newline in nonce accepted")
	}
}
