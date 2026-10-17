package identity_test

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	memoryidentity "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
)

func TestCredentialBytesAreIsolated(t *testing.T) {
	store := memoryidentity.NewRepository()
	handle := []byte("homeharbor-admin-v1")
	credential := webauthn.Credential{ID: []byte{1}, PublicKey: []byte{2}}
	credential.Authenticator.AAGUID = []byte{3}
	credential.Attestation.Object = []byte{4}

	if err := store.SaveBootstrapCredential(context.Background(), handle, credential); err != nil {
		t.Fatal(err)
	}

	credential.PublicKey[0] = 9
	credential.Authenticator.AAGUID[0] = 9

	got, err := store.Credential(context.Background(), handle, []byte{1})
	if err != nil {
		t.Fatal(err)
	}

	if got.PublicKey[0] != 2 || got.Authenticator.AAGUID[0] != 3 {
		t.Fatalf("input alias = %#v", got)
	}

	got.PublicKey[0] = 8
	got.Attestation.Object[0] = 8

	again, err := store.Credential(context.Background(), handle, []byte{1})
	if err != nil {
		t.Fatal(err)
	}

	if again.PublicKey[0] != 2 || again.Attestation.Object[0] != 4 {
		t.Fatalf("output alias = %#v", again)
	}
}
