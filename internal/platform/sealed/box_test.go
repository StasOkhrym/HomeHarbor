package sealed_test

import (
	"bytes"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/platform/sealed"
)

func TestSealedPayloadIsRandomizedAndBoundToOwnerAndPurpose(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	box, err := sealed.New(key, "identity.totp")
	if err != nil {
		t.Fatal(err)
	}

	other, err := sealed.New(key, "notification.delivery")
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("private test seed")

	first, err := box.Seal("account-a", plaintext)
	if err != nil {
		t.Fatal(err)
	}

	second, err := box.Seal("account-a", plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first, second) || bytes.Contains(first, plaintext) {
		t.Fatal("sealed values reused a nonce or exposed plaintext")
	}

	opened, err := box.Open("account-a", first)

	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatal("owned payload did not decrypt", err)
	}

	if _, err := box.Open("account-b", first); err == nil {
		t.Fatal("ciphertext crossed accounts")
	}

	if _, err := other.Open("account-a", first); err == nil {
		t.Fatal("ciphertext crossed security purposes")
	}

	for _, candidate := range [][]byte{nil, first[:4], append([]byte{2}, first[1:]...)} {
		if _, err := box.Open("account-a", candidate); err == nil {
			t.Fatal("invalid ciphertext admitted")
		}
	}

	tampered := bytes.Clone(first)
	tampered[len(tampered)-1] ^= 1

	if _, err := box.Open("account-a", tampered); err == nil {
		t.Fatal("modified ciphertext admitted")
	}

	if _, err := box.Seal("", plaintext); err == nil {
		t.Fatal("unscoped plaintext admitted")
	}
}
