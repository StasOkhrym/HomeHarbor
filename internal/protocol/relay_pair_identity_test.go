package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestRelayPairSessionCanonicalAndSymmetric(t *testing.T) {
	raw, err := os.ReadFile("../../api/testdata/relay-pair.json")
	if err != nil {
		t.Fatal(err)
	}

	var vector struct {
		Network string `json:"network_id"`
		Root    []byte `json:"root_public_key"`
		A       string `json:"device_a"`
		B       string `json:"device_b"`
		Payload string `json:"payload_hex"`
		Session string `json:"session_id"`
	}

	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}

	for _, pair := range [][2]string{{vector.A, vector.B}, {vector.B, vector.A}} {
		got, err := RelayPairSessionID(vector.Network, vector.Root, pair[0], pair[1])

		if err != nil || got != vector.Session {
			t.Fatalf("canonical pair mismatch: %q %v", got, err)
		}

		payload, err := relayPairPayload(vector.Network, vector.Root, pair[0], pair[1])

		if err != nil || hex.EncodeToString(payload) != vector.Payload {
			t.Fatal("canonical payload mismatch")
		}
	}

	for _, changed := range []struct {
		network string
		root    []byte
		a, b    string
	}{
		{"other", vector.Root, vector.A, vector.B},
		{vector.Network, bytes.Repeat([]byte{7}, 32), vector.A, vector.B},
		{vector.Network, vector.Root, "client-2", vector.B},
	} {
		got, err := RelayPairSessionID(changed.network, changed.root, changed.a, changed.b)

		if err != nil || got == vector.Session {
			t.Fatal("pair is not bound to root/network/devices")
		}
	}
}

func TestRelayPairSessionRejectsAmbiguousOrUnboundedIdentity(t *testing.T) {
	root := bytes.Repeat([]byte{1}, 32)
	for _, value := range []struct {
		network string
		root    []byte
		a, b    string
	}{
		{"", root, "a", "b"},
		{"home", root[:31], "a", "b"},
		{"home", root, "a", "a"},
		{"home", root, "", "b"},
		{"home", root, "a\x00b", "c"},
		{"home", root, "a b", "c"},
		{"home", root, "пристрій", "b"},
		{"home", root, string(bytes.Repeat([]byte{'a'}, 129)), "b"},
		{string(bytes.Repeat([]byte{'a'}, 257)), root, "a", "b"},
		{string([]byte{0xff}), root, "a", "b"},
	} {
		if _, err := RelayPairSessionID(value.network, value.root, value.a, value.b); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}
