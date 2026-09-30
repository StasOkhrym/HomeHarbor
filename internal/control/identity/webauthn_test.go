package identity

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestMemoryStoreAllowsOnlyOneBootstrapCredential(t *testing.T) {
	store := NewMemoryStore()
	var successes atomic.Int32
	var group sync.WaitGroup
	for index := range 8 {
		group.Add(1)
		go func(id byte) {
			defer group.Done()
			if store.SaveCredential(context.Background(), adminUserHandle, webauthn.Credential{ID: []byte{id}}) == nil {
				successes.Add(1)
			}
		}(byte(index))
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful credential inserts = %d", successes.Load())
	}
}

func TestBeginBootstrapStoresEncryptedOneTimeCeremony(t *testing.T) {
	store := NewMemoryStore()
	now := time.Unix(100, 0)
	service := newPasskeyTestService(t, store, func() time.Time { return now })

	begin, err := service.BeginBootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if begin.CeremonyID == "" || len(begin.Options) == 0 {
		t.Fatalf("begin = %#v", begin)
	}
	stored := store.ceremonies[hashToken(begin.CeremonyID)]
	if bytes.Contains(stored.PayloadCiphertext, []byte(`"challenge"`)) {
		t.Fatal("ceremony challenge stored as plaintext")
	}

	// An invalid response still consumes the ceremony. Retrying the same
	// challenge would turn parsing errors into a replay window.
	if _, err = service.FinishBootstrap(context.Background(), begin.CeremonyID, []byte(`{}`)); err == nil {
		t.Fatal("invalid WebAuthn response succeeded")
	}
	if _, err = service.FinishBootstrap(context.Background(), begin.CeremonyID, []byte(`{}`)); !errors.Is(err, ErrInvalidCeremony) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestBootstrapClosesAfterCredentialExists(t *testing.T) {
	store := NewMemoryStore()
	store.credentials[string(adminUserHandle)] = []webauthn.Credential{{ID: []byte("credential")}}
	service := newPasskeyTestService(t, store, time.Now)
	if _, err := service.BeginBootstrap(context.Background()); !errors.Is(err, ErrBootstrapClosed) {
		t.Fatalf("error = %v", err)
	}
}

func TestExpiredCeremonyFailsBeforeResponseParsing(t *testing.T) {
	store := NewMemoryStore()
	now := time.Unix(100, 0)
	service := newPasskeyTestService(t, store, func() time.Time { return now })
	begin, err := service.BeginBootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if _, err = service.FinishBootstrap(context.Background(), begin.CeremonyID, []byte(`not-json`)); !errors.Is(err, ErrInvalidCeremony) {
		t.Fatalf("error = %v", err)
	}
}

func TestCredentialCounterCannotRegress(t *testing.T) {
	store := NewMemoryStore()
	stored := webauthn.Credential{ID: []byte("credential")}
	stored.Authenticator.SignCount = 8
	store.credentials[string(adminUserHandle)] = []webauthn.Credential{stored}
	regressed := stored
	regressed.Authenticator.SignCount = 7
	if err := store.UpdateCredential(context.Background(), adminUserHandle, regressed); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("error = %v", err)
	}
	if got := store.credentials[string(adminUserHandle)][0].Authenticator.SignCount; got != 8 {
		t.Fatalf("stored counter = %d", got)
	}
}

func newPasskeyTestService(t *testing.T, store *MemoryStore, now func() time.Time) *PasskeyService {
	t.Helper()
	service, err := NewPasskeyService(PasskeyConfig{RPID: "tunnel.example.com", RPOrigin: "https://tunnel.example.com", EncryptionKey: bytes.Repeat([]byte{7}, 32), CeremonyTTL: 10 * time.Minute}, store, store, now, &sequenceReader{next: 'p'})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
