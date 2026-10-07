package protocol_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func TestActivationGoldenBytes(t *testing.T) {
	challenge := protocol.ClaimChallenge{
		Version:   1,
		NetworkID: "home",
		InviteID:  "invite-1",
		DeviceID:  "device-1",
		Nonce:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ExpiresAt: 1790000000,
	}

	proof, err := protocol.SignClaim(challenge, ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}

	payload, err := protocol.ClaimPayload(challenge)
	if err != nil {
		t.Fatal(err)
	}

	wire, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}

	got := struct {
		SignedJSON  string `json:"signed_json"`
		PayloadCBOR string `json:"payload_cbor"`
	}{string(wire), hex.EncodeToString(payload)}

	data, err := os.ReadFile("../../api/testdata/activation.json")
	if err != nil {
		t.Fatal(err)
	}

	var want struct {
		SignedJSON  string `json:"signed_json"`
		PayloadCBOR string `json:"payload_cbor"`
	}

	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Fatalf("activation bytes = %+v, want %+v", got, want)
	}
}
