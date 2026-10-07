package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	memoryidentity "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
)

// Only authenticator verification is doubled here. Registration exclusivity,
// stored credentials, recovery hashes and session creation use identity stores.
// WebAuthn parsing/cryptography remain covered by the identity suite.
type persistedPasskeys struct {
	*identity.PasskeyService
	store *memoryidentity.Repository
}

var bootstrapTestHandle = []byte("homeharbor-admin-v1")

func (p *persistedPasskeys) FinishBootstrap(
	ctx context.Context,
	_ string,
	_ []byte,
) (webauthn.Credential, error) {
	credential := webauthn.Credential{ID: []byte("test-passkey")}
	return credential, p.store.SaveCredential(ctx, bootstrapTestHandle, credential)
}

func (p *persistedPasskeys) FinishLogin(
	ctx context.Context,
	_ string,
	_ []byte,
) (webauthn.Credential, error) {
	return p.store.Credential(ctx, bootstrapTestHandle, []byte("test-passkey"))
}

type bootstrapSessions struct {
	AdminSessions
	recoveryFailure error
	sessionFailure  error
	recoveryCalls   int
}

func (s *bootstrapSessions) GenerateRecoveryCodes(
	ctx context.Context,
	count int,
) ([]string, error) {
	s.recoveryCalls++
	if s.recoveryFailure != nil {
		return nil, s.recoveryFailure
	}
	return s.AdminSessions.GenerateRecoveryCodes(ctx, count)
}

func (s *bootstrapSessions) CreateSession(
	ctx context.Context,
	ttl time.Duration,
) (identity.IssuedSession, error) {
	if s.sessionFailure != nil {
		return identity.IssuedSession{}, s.sessionFailure
	}
	return s.AdminSessions.CreateSession(ctx, ttl)
}

func bootstrapFixture(t *testing.T) (*BrowserAuth, *persistedPasskeys, *bootstrapSessions) {
	t.Helper()
	store := memoryidentity.NewRepository()
	service, err := identity.NewPasskeyService(identity.PasskeyConfig{
		RPID:          "tunnel.example.com",
		RPOrigin:      "https://tunnel.example.com",
		EncryptionKey: bytes.Repeat([]byte{7}, 32),
		CeremonyTTL:   time.Minute,
	}, store, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	passkeys := &persistedPasskeys{PasskeyService: service, store: store}
	sessions := &bootstrapSessions{AdminSessions: identity.NewService(store, store, nil, nil)}
	auth, err := NewBrowserAuth(BrowserAuthConfig{
		Origin:     "https://tunnel.example.com",
		SigningKey: bytes.Repeat([]byte{8}, 32),
		SessionTTL: time.Hour,
		SetupState: passkeys,
	}, passkeys, sessions)
	if err != nil {
		t.Fatal(err)
	}
	return auth, passkeys, sessions
}

func bootstrapPost(auth *BrowserAuth, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path,
		strings.NewReader(`{"ceremony_id":"test","response":{}}`))
	request.Header.Set("Origin", "https://tunnel.example.com")
	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, request)
	return response
}

func assertBootstrapClosed(t *testing.T, passkeys *persistedPasskeys) {
	t.Helper()

	if _, err := passkeys.BeginBootstrap(
		context.Background(),
	); !errors.Is(
		err,
		identity.ErrBootstrapClosed,
	) {
		t.Fatalf("registration reopened: %v", err)
	}

	credentials, err := passkeys.store.Credentials(context.Background(), bootstrapTestHandle)

	if err != nil || len(credentials) != 1 {
		t.Fatalf("expected one persisted passkey: count=%d error=%v", len(credentials), err)
	}
}

func TestBootstrapRecoveryFailureKeepsRegistrationClosed(t *testing.T) {
	auth, passkeys, sessions := bootstrapFixture(t)
	sessions.recoveryFailure = errors.New("private storage details")

	response := bootstrapPost(auth, "/bootstrap/finish")

	assertBootstrapClosed(t, passkeys)

	if response.Code != http.StatusInternalServerError || len(response.Result().Cookies()) != 0 ||
		!strings.Contains(response.Body.String(), "bootstrap_recovery_unavailable") ||
		strings.Contains(response.Body.String(), "private storage details") {
		t.Fatalf("untruthful partial failure: %d %s", response.Code, response.Body)
	}
}

func TestBootstrapSessionFailureDoesNotClaimSuccess(t *testing.T) {
	auth, passkeys, sessions := bootstrapFixture(t)
	sessions.sessionFailure = identity.ErrSecurityStateUnavailable

	response := bootstrapPost(auth, "/bootstrap/finish")

	assertBootstrapClosed(t, passkeys)

	if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 ||
		!strings.Contains(response.Body.String(), "bootstrap_session_unavailable") ||
		strings.Contains(response.Body.String(), "recovery_codes") {
		t.Fatalf("untruthful session failure: %d %s", response.Code, response.Body)
	}
}

func TestPersistedBootstrapPasskeyCanLoginAfterFailure(t *testing.T) {
	for _, failure := range []string{"recovery", "session"} {
		t.Run(failure, func(t *testing.T) {
			auth, passkeys, sessions := bootstrapFixture(t)
			if failure == "recovery" {
				sessions.recoveryFailure = errors.New("unavailable")
			} else {
				sessions.sessionFailure = identity.ErrSecurityStateUnavailable
			}

			if response := bootstrapPost(auth, "/bootstrap/finish"); response.Code < 400 {
				t.Fatal("failure reported success")
			}

			assertBootstrapClosed(t, passkeys)
			sessions.recoveryFailure, sessions.sessionFailure = nil, nil

			response := bootstrapPost(auth, "/login/finish")

			if response.Code != http.StatusNoContent || len(response.Result().Cookies()) != 2 {
				t.Fatalf("persisted passkey cannot log in: %d %s", response.Code, response.Body)
			}
			if sessions.recoveryCalls != 1 {
				t.Fatal("sign-in regenerated recovery codes")
			}
		})
	}
}

func TestBootstrapResponseLossDoesNotRepeatRecoveryCodes(t *testing.T) {
	auth, passkeys, sessions := bootstrapFixture(t)

	// Discard the successful response as a disconnected browser would.
	if response := bootstrapPost(auth, "/bootstrap/finish"); response.Code != http.StatusOK {
		t.Fatal(response.Body)
	}

	response := bootstrapPost(auth, "/bootstrap/finish")

	assertBootstrapClosed(t, passkeys)

	if response.Code != http.StatusUnauthorized || sessions.recoveryCalls != 1 ||
		strings.Contains(
			response.Body.String(),
			"recovery_codes",
		) || len(response.Result().Cookies()) != 0 {
		t.Fatalf("replayed bootstrap delivered secrets: %d %s", response.Code, response.Body)
	}
}
