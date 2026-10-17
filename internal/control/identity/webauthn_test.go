package identity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/identity"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
)

var adminUserHandle = []byte("homeharbor-admin-v1")

func TestMemoryStoreAllowsOnlyOneBootstrapCredential(t *testing.T) {
	store := memorystore.NewRepository()
	var successes atomic.Int32
	var group sync.WaitGroup
	for index := range 8 {
		group.Add(1)
		go func(id byte) {
			defer group.Done()

			if store.SaveBootstrapCredential(
				context.Background(),
				adminUserHandle,
				webauthn.Credential{ID: []byte{id}},
			) == nil {
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
	store := memorystore.NewRepository()

	now := time.Unix(100, 0)

	service := newPasskeyTestService(t, store, func() time.Time { return now })

	begin, err := service.BeginBootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if begin.CeremonyID == "" || len(begin.Options) == 0 {
		t.Fatalf("begin = %#v", begin)
	}

	stored, ok := store.StoredCeremony(sha256.Sum256([]byte(begin.CeremonyID)))
	if !ok {
		t.Fatal("ceremony not stored")
	}
	if bytes.Contains(stored.PayloadCiphertext, []byte(`"challenge"`)) {
		t.Fatal("ceremony challenge stored as plaintext")
	}

	// An invalid response still consumes the ceremony. Retrying the same
	// challenge would turn parsing errors into a replay window.
	if _, err = service.FinishBootstrap(
		context.Background(),
		begin.CeremonyID,
		[]byte(`{}`),
	); err == nil {
		t.Fatal("invalid WebAuthn response succeeded")
	}

	if _, err = service.FinishBootstrap(
		context.Background(),
		begin.CeremonyID,
		[]byte(`{}`),
	); !errors.Is(
		err,
		domainpkg.ErrInvalidCeremony,
	) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestPasskeyCeremoniesUseSecureDefaults(t *testing.T) {
	for _, kind := range []string{"bootstrap", "login"} {
		t.Run(kind, func(t *testing.T) {
			store := memorystore.NewRepository()
			service, err := domainpkg.NewPasskeyService(domainpkg.PasskeyConfig{
				RPID:          "tunnel.example.com",
				RPOrigin:      "https://tunnel.example.com",
				EncryptionKey: bytes.Repeat([]byte{7}, 32),
				CeremonyTTL:   time.Minute,
			}, store, store, nil, nil)
			if err != nil {
				t.Fatal(err)
			}

			begin := service.BeginBootstrap
			if kind == "login" {
				begin = service.BeginLogin
			}

			first, err := begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}

			second, err := begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}

			if first.CeremonyID == "" || first.CeremonyID == second.CeremonyID {
				t.Fatal("ceremonies must have distinct nonempty identifiers")
			}

			if kind == "login" {
				_, err = service.FinishLogin(context.Background(), first.CeremonyID, []byte(`{}`))
			} else {
				_, err = service.FinishBootstrap(
					context.Background(),
					first.CeremonyID,
					[]byte(`{}`),
				)
			}

			if err == nil || errors.Is(err, domainpkg.ErrInvalidCeremony) {
				t.Fatalf("expected response parsing after ceremony decryption: %v", err)
			}

			if registered, err := store.HasCredentials(
				context.Background(),
			); err != nil ||
				registered {
				t.Fatal("starting a ceremony must not create credentials")
			}
		})
	}
}

func TestPasskeyEntropyFailureDoesNotPersistCeremony(t *testing.T) {
	store := memorystore.NewRepository()
	service, err := domainpkg.NewPasskeyService(domainpkg.PasskeyConfig{
		RPID:          "tunnel.example.com",
		RPOrigin:      "https://tunnel.example.com",
		EncryptionKey: bytes.Repeat([]byte{7}, 32),
		CeremonyTTL:   time.Minute,
	}, store, store, time.Now, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.BeginBootstrap(context.Background()); err == nil {
		t.Fatal("entropy failure must reject the ceremony")
	}

	if store.CeremonyCount() != 0 {
		t.Fatal("entropy failure persisted a ceremony")
	}
}

func TestBootstrapClosesAfterCredentialExists(t *testing.T) {
	store := memorystore.NewRepository()

	if err := store.SaveBootstrapCredential(
		context.Background(),
		adminUserHandle,
		webauthn.Credential{ID: []byte("credential")},
	); err != nil {
		t.Fatal(err)
	}

	service := newPasskeyTestService(t, store, time.Now)

	if _, err := service.BeginBootstrap(
		context.Background(),
	); !errors.Is(
		err,
		domainpkg.ErrBootstrapClosed,
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestExpiredCeremonyFailsBeforeResponseParsing(t *testing.T) {
	store := memorystore.NewRepository()

	now := time.Unix(100, 0)

	service := newPasskeyTestService(t, store, func() time.Time { return now })

	begin, err := service.BeginBootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(11 * time.Minute)

	if _, err = service.FinishBootstrap(
		context.Background(),
		begin.CeremonyID,
		[]byte(`not-json`),
	); !errors.Is(
		err,
		domainpkg.ErrInvalidCeremony,
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestCredentialCounterCannotRegress(t *testing.T) {
	store := memorystore.NewRepository()
	stored := webauthn.Credential{ID: []byte("credential")}
	stored.Authenticator.SignCount = 8

	if err := store.SaveBootstrapCredential(
		context.Background(),
		adminUserHandle,
		stored,
	); err != nil {
		t.Fatal(err)
	}

	regressed := stored
	regressed.Authenticator.SignCount = 7

	if err := store.UpdateCredential(
		context.Background(),
		adminUserHandle,
		regressed,
	); !errors.Is(
		err,
		domainpkg.ErrInvalidCredential,
	) {
		t.Fatalf("error = %v", err)
	}

	unchanged, err := store.Credential(context.Background(), adminUserHandle, stored.ID)
	if err != nil {
		t.Fatal(err)
	}

	if got := unchanged.Authenticator.SignCount; got != 8 {
		t.Fatalf("stored counter = %d", got)
	}
}

func newPasskeyTestService(
	t *testing.T,
	store *memorystore.Repository,
	now func() time.Time,
) *domainpkg.PasskeyService {
	t.Helper()

	service, err := domainpkg.NewPasskeyService(
		domainpkg.PasskeyConfig{
			RPID:          "tunnel.example.com",
			RPOrigin:      "https://tunnel.example.com",
			EncryptionKey: bytes.Repeat([]byte{7}, 32),
			CeremonyTTL:   10 * time.Minute,
		},
		store,
		store,
		now,
		&sequenceReader{next: 'p'},
	)
	if err != nil {
		t.Fatal(err)
	}

	return service
}

func TestPasswordAccountCannotReopenLegacyBootstrapOrLogin(t *testing.T) {
	store := memorystore.NewRepository()

	store.SetAccountForTest(
		domainpkg.Account{
			ID:           domainpkg.OwnerAccountID,
			Role:         domainpkg.RoleOwner,
			Status:       domainpkg.AccountActive,
			AuthVersion:  2,
			Email:        "owner@example.test",
			PasswordHash: "hash",
			UserHandle:   adminUserHandle,
		},
	)
	service := newPasskeyTestService(t, store, time.Now)

	// A configured owner can use TOTP without keeping a passkey. An empty global
	// credential table must never reopen first-owner registration in that case.
	if _, err := service.BeginBootstrap(
		t.Context(),
	); !errors.Is(
		err,
		domainpkg.ErrBootstrapClosed,
	) {
		t.Fatalf("active password account reopened bootstrap: %v", err)
	}

	if _, err := service.BeginLogin(t.Context()); !errors.Is(err, domainpkg.ErrInvalidCredential) {
		t.Fatalf("active password account accepted standalone passkey login: %v", err)
	}
}
