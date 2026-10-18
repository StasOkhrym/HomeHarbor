package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/events"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	authenticator "github.com/StasOkhrym/homeharbor/internal/testutil/webauthn"
)

func accountPrincipal(t *testing.T, store *identity.Service) identity.Principal {
	t.Helper()

	issued, err := store.CreateSession(
		t.Context(),
		identity.SessionRequest{
			AccountID:   identity.OwnerAccountID,
			AuthVersion: 2,
			Purpose:     identity.SessionAdmin,
			Method:      "totp",
			TTL:         time.Hour,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	principal, err := store.ValidateSession(t.Context(), issued.Token)
	if err != nil {
		t.Fatal(err)
	}

	return principal
}

func accountRequest(
	t *testing.T,
	auth *BrowserAuth,
	principal identity.Principal,
	path, body string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))

	request = request.WithContext(identity.WithPrincipal(request.Context(), principal))
	response := httptest.NewRecorder()

	auth.AccountHandler().ServeHTTP(response, request)
	return response
}

func TestAccountManagementRequiresCurrentRecentPersonalPrincipal(t *testing.T) {
	auth, store, sessions := personalAuthFixture(t, true)

	principal := accountPrincipal(t, sessions)
	for _, tc := range []struct {
		name      string
		principal identity.Principal
		want      int
	}{
		{"anonymous", identity.Principal{}, http.StatusUnauthorized},
		{"migration", identity.Principal{AccountID: principal.AccountID, Role: principal.Role, AuthVersion: principal.AuthVersion, Purpose: identity.SessionMigration}, http.StatusUnauthorized},
		{"stale-epoch", func() identity.Principal { p := principal; p.AuthVersion--; return p }(), http.StatusUnauthorized},
		{"old-session", func() identity.Principal {
			p := principal
			p.AuthenticatedAt = p.AuthenticatedAt.Add(-5 * time.Minute)

			return p
		}(), http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := accountRequest(t, auth, tc.principal, "/recovery-codes", "{}")

			if response.Code != tc.want {
				t.Fatalf("status %d: %s", response.Code, response.Body.String())
			}
		})
	}

	response := accountRequest(t, auth, principal, "/recovery-codes", "{}")
	var result struct {
		Codes []string `json:"codes"`
	}

	err := json.Unmarshal(response.Body.Bytes(), &result)

	if response.Code != http.StatusOK || err != nil || len(result.Codes) != 10 ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("recovery response %d %s %v", response.Code, response.Body.String(), err)
	}

	state, err := store.FactorState(
		t.Context(),
		identity.AccountScope{
			AccountID:   principal.AccountID,
			AuthVersion: 2,
			Purpose:     identity.SessionAdmin,
		},
	)

	if err != nil || state.RecoveryCodesRemaining != 10 {
		t.Fatal("codes not persisted", err)
	}

	response = accountRequest(t, auth, principal, "/totp/remove", "{}")

	if response.Code != http.StatusConflict {
		t.Fatalf("last factor removed: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountPasskeyEnrollmentInvalidatesExistingSession(t *testing.T) {
	auth, store, sessions := personalAuthFixture(t, true)

	principal := accountPrincipal(t, sessions)

	begin := accountRequest(t, auth, principal, "/passkeys/begin", `{"name":"MacBook"}`)
	var ceremony identity.BeginCeremony

	if err := json.Unmarshal(
		begin.Body.Bytes(),
		&ceremony,
	); err != nil ||
		begin.Code != http.StatusOK {
		t.Fatalf("begin %d %s %v", begin.Code, begin.Body.String(), err)
	}

	device := authenticator.New(t, "home.example.test", "https://home.example.test")

	response := device.Registration(t, ceremony.Options)

	payload, err := json.Marshal(
		map[string]any{"ceremony_id": ceremony.CeremonyID, "response": json.RawMessage(response)},
	)
	if err != nil {
		t.Fatal(err)
	}

	finish := accountRequest(t, auth, principal, "/passkeys/finish", string(payload))

	if finish.Code != http.StatusNoContent {
		t.Fatalf("finish %d %s", finish.Code, finish.Body.String())
	}

	for _, cookie := range finish.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.MaxAge >= 0 {
			t.Fatal("MFA change silently issued a session")
		}
	}

	account, err := store.Account(t.Context(), principal.AccountID)

	if err != nil || account.AuthVersion != 3 {
		t.Fatal("factor change failed to invalidate old sessions", err)
	}

	replay := accountRequest(t, auth, principal, "/recovery-codes", "{}")

	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("stale session used after change: %d", replay.Code)
	}
}

func TestPasskeyBeginRequiresPasswordProofAndReturnsOnlyOwnMethods(t *testing.T) {
	auth, _, _ := personalAuthFixture(t, true)
	anonymous := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/passkey/begin", bytes.NewBufferString("{}"))
	request.Header.Set("Origin", "https://home.example.test")
	auth.Handler().ServeHTTP(anonymous, request)

	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous passkey begin %d", anonymous.Code)
	}

	password := httptest.NewRequest(
		http.MethodPost,
		"/password",
		strings.NewReader(`{"email":"owner@example.test","password":"private long password"}`),
	)
	password.Header.Set("Origin", "https://home.example.test")
	proof := httptest.NewRecorder()

	auth.Handler().ServeHTTP(proof, password)

	if proof.Code != http.StatusOK {
		t.Fatal(proof.Code)
	}

	page := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	for _, cookie := range proof.Result().Cookies() {
		if cookie.Name == preauthCookieName && cookie.MaxAge > 0 {
			page.AddCookie(cookie)
		}
	}

	view := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(view, page)

	if view.Code != http.StatusOK || !strings.Contains(view.Body.String(), `id="factor-code"`) ||
		strings.Contains(view.Body.String(), `id="factor-passkey"`) {
		t.Fatalf("wrong method availability %d %s", view.Code, view.Body.String())
	}

	expired := httptest.NewRequest(http.MethodGet, "/admin/login", nil)

	expired.AddCookie(&http.Cookie{Name: preauthCookieName, Value: strings.Repeat("z", 43)})
	view = httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(view, expired)

	if view.Code != http.StatusOK || !strings.Contains(view.Body.String(), `id="password-login"`) {
		t.Fatal("expired password proof trapped factor page", view.Code)
	}
}

func TestLoginReturnTargetIsAllowlisted(t *testing.T) {
	auth, _, _ := personalAuthFixture(t, true)
	for _, tc := range []struct{ query, want string }{{"security", "security"}, {"https%3A%2F%2Fattacker.example", ""}} {
		request := httptest.NewRequest(http.MethodGet, "/admin/login?return_to="+tc.query, nil)
		response := httptest.NewRecorder()

		auth.LoginHandler().ServeHTTP(response, request)

		if !strings.Contains(response.Body.String(), `data-login-return="`+tc.want+`"`) {
			t.Fatal("unsafe or missing return target", tc.query)
		}
	}
}

func TestPersonalPasskeyHTTPCompletesPasswordBoundLogin(t *testing.T) {
	auth, _, sessions := personalAuthFixture(t, true)

	principal := accountPrincipal(t, sessions)
	var enrollment identity.BeginCeremony

	begin := accountRequest(t, auth, principal, "/passkeys/begin", `{"name":"MacBook"}`)

	if err := json.Unmarshal(
		begin.Body.Bytes(),
		&enrollment,
	); err != nil ||
		begin.Code != http.StatusOK {
		t.Fatal("enrollment begin", begin.Code, err)
	}

	device := authenticator.New(t, "home.example.test", "https://home.example.test")

	payload, err := json.Marshal(
		map[string]any{
			"ceremony_id": enrollment.CeremonyID,
			"response":    json.RawMessage(device.Registration(t, enrollment.Options)),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if response := accountRequest(
		t,
		auth,
		principal,
		"/passkeys/finish",
		string(payload),
	); response.Code != http.StatusNoContent {
		t.Fatal("enrollment finish", response.Code)
	}

	password := httptest.NewRequest(
		http.MethodPost,
		"/password",
		strings.NewReader(`{"email":"owner@example.test","password":"private long password"}`),
	)
	password.Header.Set("Origin", "https://home.example.test")
	proof := httptest.NewRecorder()

	auth.Handler().ServeHTTP(proof, password)

	if proof.Code != http.StatusOK {
		t.Fatal("password", proof.Code)
	}

	var preauth *http.Cookie
	for _, cookie := range proof.Result().Cookies() {
		if cookie.Name == preauthCookieName && cookie.MaxAge > 0 {
			preauth = cookie
		}
	}

	if preauth == nil {
		t.Fatal("password proof missing")
	}

	request := httptest.NewRequest(http.MethodPost, "/passkey/begin", strings.NewReader("{}"))
	request.Header.Set("Origin", "https://home.example.test")
	request.AddCookie(preauth)
	assertion := httptest.NewRecorder()

	auth.Handler().ServeHTTP(assertion, request)
	var ceremony identity.BeginCeremony

	if err := json.Unmarshal(
		assertion.Body.Bytes(),
		&ceremony,
	); err != nil ||
		assertion.Code != http.StatusOK {
		t.Fatal("assertion begin", assertion.Code, err)
	}

	payload, err = json.Marshal(
		identity.SecondFactorProof{
			Method:     "passkey",
			CeremonyID: ceremony.CeremonyID,
			Response:   device.Assertion(t, ceremony.Options),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	request = httptest.NewRequest(http.MethodPost, "/factor", bytes.NewReader(payload))
	request.Header.Set("Origin", "https://home.example.test")
	request.AddCookie(preauth)
	response := httptest.NewRecorder()

	auth.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("assertion finish %d %s", response.Code, response.Body.String())
	}

	protected := httptest.NewRequest(http.MethodGet, "/admin/security", nil)
	for _, cookie := range response.Result().Cookies() {
		protected.AddCookie(cookie)
	}

	authenticated, err := auth.AdminPrincipal(t.Context(), protected)

	if err != nil || authenticated.AccountID != identity.OwnerAccountID ||
		authenticated.AuthVersion != 3 ||
		authenticated.Method != "passkey" {
		t.Fatal("wrong personal session", authenticated, err)
	}
}

func TestAccountSessionRevocationIsOwnScopedAndExpiresBrowserProofs(t *testing.T) {
	auth, store, sessions := personalAuthFixture(t, true)

	principal := accountPrincipal(t, sessions)
	sink := &accountEventSink{}
	auth.auditor = events.NewIdentityAuditor(sink, nil)
	request := identity.SessionRequest{
		AccountID:   principal.AccountID,
		AuthVersion: principal.AuthVersion,
		Purpose:     identity.SessionAdmin,
		Method:      "totp",
		TTL:         time.Hour,
	}

	old, err := sessions.CreateSession(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		principal identity.Principal
		body      string
		status    int
	}{
		{principal, `{"account_id":"another-admin"}`, http.StatusBadRequest},
		{func() identity.Principal {
			p := principal
			p.AuthenticatedAt = p.AuthenticatedAt.Add(-5 * time.Minute)

			return p
		}(), "{}", http.StatusForbidden},
		{func() identity.Principal { p := principal; p.AuthVersion--; return p }(), "{}", http.StatusUnauthorized},
		{identity.Principal{}, "{}", http.StatusUnauthorized},
	} {
		response := accountRequest(t, auth, tc.principal, "/sessions/revoke-all", tc.body)

		if response.Code != tc.status {
			t.Fatal("unverified revocation admitted", response.Code, tc.status)
		}
	}

	before, err := store.Account(t.Context(), principal.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	response := accountRequest(t, auth, principal, "/sessions/revoke-all", "{}")

	if response.Code != http.StatusNoContent ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("scoped session revocation unavailable", response.Code)
	}

	expired := map[string]bool{}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Value == "" && cookie.MaxAge < 0 {
			expired[cookie.Name] = true
		}
	}

	for _, name := range []string{sessionCookieName, csrfCookieName, preauthCookieName, enrollmentCookieName} {
		if !expired[name] {
			t.Fatal("browser proof survived sign-out everywhere", name)
		}
	}

	if _, err := sessions.ValidateSession(
		t.Context(),
		old.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("old session remained authorized", err)
	}

	after, err := store.Account(t.Context(), principal.AccountID)

	if err != nil || after.AuthVersion != before.AuthVersion+1 ||
		after.PasswordHash != before.PasswordHash {
		t.Fatal("HTTP revocation changed password", err)
	}

	event := audit.PublicEvent(sink.event)

	if event.Action != "admin.sessions_revoked" || event.ActorID != principal.AccountID ||
		event.Metadata["auth_method"] != "password_totp" ||
		audit.ActionLabel(event.Action) == "Other activity" {
		t.Fatal("unattributed session revocation history", event.Action)
	}
}
