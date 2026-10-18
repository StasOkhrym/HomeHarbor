package auth

import (
	"bytes"
	"context"
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
	memory "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
	authenticator "github.com/StasOkhrym/homeharbor/internal/testutil/webauthn"
)

type mailActionsStub struct{ failure error }

func (s mailActionsStub) RequestPasswordReset(context.Context, string) error { return s.failure }
func (s mailActionsStub) RequestEmailVerification(context.Context, identity.Principal) error {
	return s.failure
}

func (s mailActionsStub) ResetPassword(
	context.Context,
	string,
	string,
) (identity.AccountSubject, error) {
	return identity.AccountSubject{ID: "invited", Email: "invited@example.test"}, s.failure
}

func (s mailActionsStub) AcceptInvitation(
	context.Context,
	string,
	string,
) (identity.AccountSubject, error) {
	return identity.AccountSubject{ID: "invited", Email: "invited@example.test"}, s.failure
}

func (s mailActionsStub) VerifyEmail(context.Context, string) (identity.AccountSubject, error) {
	return identity.AccountSubject{ID: "invited", Email: "invited@example.test"}, s.failure
}

func (s mailActionsStub) InviteAdmin(
	context.Context,
	identity.Principal,
	string,
) (identity.AccountSubject, error) {
	return identity.AccountSubject{ID: "invited", Email: "invited@example.test"}, s.failure
}

func (s mailActionsStub) RevokeAdmin(
	context.Context,
	identity.Principal,
	string,
) (identity.AccountSubject, error) {
	return identity.AccountSubject{ID: "invited", Email: "invited@example.test"}, s.failure
}

func mailAuthFixture(t *testing.T) (*BrowserAuth, *memory.Repository) {
	t.Helper()
	auth, store, sessions := personalAuthFixture(t, true)

	now := time.Unix(2000000000, 0).UTC()
	clock := func() time.Time { return now }

	store.SetAccountForTest(
		identity.Account{
			ID:              "invited",
			Email:           "invited@example.test",
			Role:            identity.RoleAdmin,
			Status:          identity.AccountInvited,
			AuthVersion:     3,
			PasswordHash:    fixturePasswordHash(t),
			UserHandle:      []byte("invited-user"),
			EmailVerifiedAt: &now,
		},
	)

	passkeys, err := identity.NewPasskeyService(
		identity.PasskeyConfig{
			RPID:          "home.example.test",
			RPOrigin:      "https://home.example.test",
			EncryptionKey: bytes.Repeat([]byte{7}, 32),
			CeremonyTTL:   time.Minute,
		},
		store,
		store,
		clock,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	factors, err := identity.NewMFAService(
		identity.MFAConfig{EncryptionKey: bytes.Repeat([]byte{7}, 32)},
		store,
		passkeys,
		sessions,
		clock,
		bytes.NewReader([]byte(strings.Repeat("12345678901234567890", 20))),
	)
	if err != nil {
		t.Fatal(err)
	}

	hasher, err := identity.NewPasswordHasher(1)
	if err != nil {
		t.Fatal(err)
	}

	enrollment, err := identity.NewEnrollmentService(
		store,
		memory.NewRepository(),
		hasher,
		factors,
		clock,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	auth.enrollment = enrollment
	auth.mail = mailActionsStub{}

	return auth, store
}

func mailRequest(
	t *testing.T,
	auth *BrowserAuth,
	path, body, origin string,
	cookies ...*http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Origin", origin)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	response := httptest.NewRecorder()

	auth.Handler().ServeHTTP(response, request)
	return response
}

func proofCookie(t *testing.T, response *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name && cookie.Value != "" && cookie.MaxAge >= 0 {
			return cookie
		}
	}

	t.Fatal("expected private cookie not issued")

	return nil
}

func noAdminCookie(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" && cookie.MaxAge >= 0 {
			t.Fatal("email/setup action issued administrative authority")
		}
	}
}

func TestEmailActionsRequireOriginAndNeverIssueAdminSession(t *testing.T) {
	auth, _ := mailAuthFixture(t)
	for _, route := range []struct{ path, body string }{
		{"/password/reset/request", `{"email":"missing@example.test"}`},
		{"/password/reset/finish", `{"token":"private-token","password":"private long password"}`},
		{"/email/verify", `{"token":"private-token"}`},
		{"/invitation/accept", `{"email":"invited@example.test","token":"private-token","password":"private long password"}`},
	} {
		t.Run(route.path, func(t *testing.T) {
			denied := mailRequest(t, auth, route.path, route.body, "https://foreign.example.test")

			if denied.Code != http.StatusForbidden {
				t.Fatal("email action accepted foreign Origin", denied.Code)
			}

			response := mailRequest(t, auth, route.path, route.body, "https://home.example.test")

			if response.Code < 200 || response.Code >= 300 ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("email action failed safe response contract", response.Code)
			}

			noAdminCookie(t, response)
			for _, private := range []string{"private-token", "private long password", "invited@example.test"} {
				if strings.Contains(response.Body.String(), private) {
					t.Fatal("email response exposed private input/recipient")
				}
			}
		})
	}

	first := mailRequest(
		t,
		auth,
		"/password/reset/request",
		`{"email":"known@example.test"}`,
		"https://home.example.test",
	)

	second := mailRequest(
		t,
		auth,
		"/password/reset/request",
		`{"email":"missing@example.test"}`,
		"https://home.example.test",
	)

	if first.Code != http.StatusAccepted || first.Code != second.Code ||
		first.Body.String() != second.Body.String() {
		t.Fatal("reset request response revealed target")
	}

	auth.mail = mailActionsStub{failure: errors.New("PRIVATE_PROVIDER_DETAIL")}

	unavailable := mailRequest(
		t,
		auth,
		"/password/reset/request",
		`{"email":"known@example.test"}`,
		"https://home.example.test",
	)

	if unavailable.Code != http.StatusServiceUnavailable ||
		strings.Contains(unavailable.Body.String(), "PRIVATE") {
		t.Fatal("unsafe mail failure diagnostic")
	}
}

func TestEnrollmentHTTPSeparatesSetupCookieAndRequiresFreshLogin(t *testing.T) {
	auth, store := mailAuthFixture(t)
	origin := "https://home.example.test"

	rejected := mailRequest(
		t,
		auth,
		"/password",
		`{"email":"invited@example.test","password":"private long password"}`,
		origin,
	)

	if rejected.Code != http.StatusUnauthorized {
		t.Fatal("invited account used normal password login", rejected.Code)
	}

	password := mailRequest(
		t,
		auth,
		"/enrollment/password",
		`{"email":"invited@example.test","password":"private long password"}`,
		origin,
	)

	if password.Code != http.StatusOK {
		t.Fatal("setup password proof failed", password.Code)
	}

	cookie := proofCookie(t, password, enrollmentCookieName)

	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" ||
		cookie.SameSite != http.SameSiteStrictMode ||
		(cookie.MaxAge < 1 || cookie.MaxAge > 300) ||
		strings.Contains(password.Body.String(), cookie.Value) {
		t.Fatal("unsafe setup cookie")
	}

	noAdminCookie(t, password)
	crossed := mailRequest(
		t,
		auth,
		"/factor",
		`{"method":"totp","code":"279037"}`,
		origin,
		&http.Cookie{Name: preauthCookieName, Value: cookie.Value},
	)

	if crossed.Code != http.StatusUnauthorized {
		t.Fatal("setup proof entered normal login namespace", crossed.Code)
	}

	missing := mailRequest(t, auth, "/enrollment/totp/begin", "{}", origin)

	if missing.Code != http.StatusUnauthorized {
		t.Fatal("setup MFA admitted without its cookie")
	}

	begin := mailRequest(t, auth, "/enrollment/totp/begin", "{}", origin, cookie)
	var setup identity.TOTPEnrollment

	if begin.Code != http.StatusOK || json.Unmarshal(begin.Body.Bytes(), &setup) != nil ||
		setup.Secret == "" {
		t.Fatal("private setup unavailable", begin.Code)
	}

	confirmed := mailRequest(
		t,
		auth,
		"/enrollment/totp/confirm",
		`{"code":"279037"}`,
		origin,
		cookie,
	)

	if confirmed.Code != http.StatusNoContent {
		t.Fatal("genuine setup code did not confirm", confirmed.Code, confirmed.Body.String())
	}

	noAdminCookie(t, confirmed)

	account, err := store.Account(t.Context(), "invited")

	if err != nil || account.Status != identity.AccountActive || account.AuthVersion != 4 {
		t.Fatal("HTTP setup did not activate once", err)
	}

	stale := mailRequest(t, auth, "/enrollment/totp/begin", "{}", origin, cookie)

	if stale.Code != http.StatusUnauthorized {
		t.Fatal("setup proof survived activation")
	}

	probe := httptest.NewRequest(http.MethodGet, "/admin/", nil)

	probe.AddCookie(cookie)

	if _, err := auth.AdminPrincipal(
		t.Context(),
		probe,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("setup cookie became an admin session", err)
	}

	fresh := mailRequest(
		t,
		auth,
		"/password",
		`{"email":"invited@example.test","password":"private long password"}`,
		origin,
	)

	if fresh.Code != http.StatusOK {
		t.Fatal("activated admin cannot start normal login", fresh.Code)
	}

	noAdminCookie(t, fresh)
}

func TestAccountMailActionsDenyAdminEscalation(t *testing.T) {
	auth, _ := mailAuthFixture(t)
	admin := identity.Principal{
		AccountID:       "other-admin",
		Role:            identity.RoleAdmin,
		Purpose:         identity.SessionAdmin,
		AuthVersion:     1,
		Method:          "totp",
		AuthenticatedAt: time.Now(),
	}
	for _, path := range []string{"/admins/invite", "/admins/other/revoke"} {
		response := accountRequest(t, auth, admin, path, `{"email":"other@example.test"}`)

		if response.Code != http.StatusForbidden {
			t.Fatal("admin escalated account management", response.Code)
		}
	}
}

func TestMailAuthCapabilitiesRequireCompleteConfiguration(t *testing.T) {
	auth, store := mailAuthFixture(t)
	for _, scenario := range []string{"mail", "enrollment", "factors", "password", "accounts", "enabled-without-actions"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := BrowserAuthConfig{
				Origin:        "https://home.example.test",
				SigningKey:    bytes.Repeat([]byte{7}, 32),
				SessionTTL:    time.Hour,
				Accounts:      store,
				PasswordLogin: auth.passwordLogin,
				Factors:       auth.factors,
				Mail:          auth.mail,
				Enrollment:    auth.enrollment,
				EmailEnabled:  true,
			}
			switch scenario {
			case "mail":
				cfg.Mail = nil
			case "enrollment":
				cfg.Enrollment = nil
			case "factors":
				cfg.Factors = nil
			case "password":
				cfg.PasswordLogin = nil
			case "accounts":
				cfg.Accounts = nil
			case "enabled-without-actions":
				cfg.Mail = nil
				cfg.Enrollment = nil
			}

			if _, err := NewBrowserAuth(cfg, auth.passkeys, auth.sessions); err == nil {
				t.Fatal("partial mail authentication capabilities were accepted")
			}
		})
	}
}

func TestEnrollmentHTTPPasskeyBindsCookieAndRequiresSignedFreshLogin(t *testing.T) {
	auth, store := mailAuthFixture(t)
	origin := "https://home.example.test"
	body := `{"email":"invited@example.test","password":"private long password"}`

	first := proofCookie(
		t,
		mailRequest(t, auth, "/enrollment/password", body, origin),
		enrollmentCookieName,
	)

	second := proofCookie(
		t,
		mailRequest(t, auth, "/enrollment/password", body, origin),
		enrollmentCookieName,
	)
	device := authenticator.New(t, "home.example.test", origin)

	begin := mailRequest(t, auth, "/enrollment/passkey/begin", `{"name":"iPhone"}`, origin, first)
	var ceremony identity.BeginCeremony

	if begin.Code != http.StatusOK || json.Unmarshal(begin.Body.Bytes(), &ceremony) != nil {
		t.Fatal("registration unavailable", begin.Code)
	}

	payload, err := json.Marshal(
		map[string]any{
			"ceremony_id": ceremony.CeremonyID,
			"response":    json.RawMessage(device.Registration(t, ceremony.Options)),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	foreign := mailRequest(t, auth, "/enrollment/passkey/finish", string(payload), origin, second)

	if foreign.Code != http.StatusUnauthorized {
		t.Fatal("another cookie completed registration", foreign.Code)
	}

	begin = mailRequest(t, auth, "/enrollment/passkey/begin", `{"name":"iPhone"}`, origin, first)

	if begin.Code != http.StatusOK || json.Unmarshal(begin.Body.Bytes(), &ceremony) != nil {
		t.Fatal("registration could not restart after rejected proof", begin.Code)
	}

	payload, err = json.Marshal(
		map[string]any{
			"ceremony_id": ceremony.CeremonyID,
			"response":    json.RawMessage(device.Registration(t, ceremony.Options)),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	finished := mailRequest(t, auth, "/enrollment/passkey/finish", string(payload), origin, first)

	if finished.Code != http.StatusNoContent {
		t.Fatal("signed registration failed", finished.Code, finished.Body.String())
	}

	noAdminCookie(t, finished)

	account, err := store.Account(t.Context(), "invited")

	if err != nil || account.Status != identity.AccountActive || account.AuthVersion != 4 {
		t.Fatal("registration did not activate invited account", err)
	}

	password := mailRequest(t, auth, "/password", body, origin)

	normal := proofCookie(t, password, preauthCookieName)

	noAdminCookie(t, password)
	begin = mailRequest(t, auth, "/passkey/begin", "{}", origin, normal)

	if begin.Code != http.StatusOK || json.Unmarshal(begin.Body.Bytes(), &ceremony) != nil {
		t.Fatal("fresh password did not enable passkey login", begin.Code)
	}

	payload, err = json.Marshal(
		map[string]any{
			"method":      "passkey",
			"ceremony_id": ceremony.CeremonyID,
			"response":    json.RawMessage(device.Assertion(t, ceremony.Options)),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	signedIn := mailRequest(t, auth, "/factor", string(payload), origin, normal)

	if signedIn.Code != http.StatusNoContent {
		t.Fatal(
			"genuine fresh password/passkey login failed",
			signedIn.Code,
			signedIn.Body.String(),
		)
	}

	session := proofCookie(t, signedIn, sessionCookieName)
	request := httptest.NewRequest(http.MethodGet, "/admin/", nil)

	request.AddCookie(session)

	principal, err := auth.AdminPrincipal(t.Context(), request)

	if err != nil || principal.AccountID != "invited" || principal.Role != identity.RoleAdmin {
		t.Fatal("fresh session belongs to wrong account", err)
	}
}

type accountEventSink struct{ event audit.Event }

func (s *accountEventSink) Write(_ context.Context, event audit.Event) error {
	s.event = event
	return nil
}

func TestEnrollmentAuditNeverBorrowsExistingOwnerIdentity(t *testing.T) {
	auth, _ := mailAuthFixture(t)
	sink := &accountEventSink{}
	auth.auditor = events.NewIdentityAuditor(sink, nil)
	origin := "https://home.example.test"

	response := mailRequest(
		t,
		auth,
		"/enrollment/password",
		`{"email":"invited@example.test","password":"private long password"}`,
		origin,
	)

	cookie := proofCookie(t, response, enrollmentCookieName)

	begin := mailRequest(t, auth, "/enrollment/totp/begin", "{}", origin, cookie)

	if begin.Code != http.StatusOK {
		t.Fatal("TOTP setup failed", begin.Code)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/enrollment/totp/confirm",
		strings.NewReader(`{"code":"279037"}`),
	)
	request.Header.Set("Origin", origin)
	request.AddCookie(cookie)
	request = request.WithContext(
		audit.WithContext(
			request.Context(),
			audit.Context{
				ActorType:      "admin",
				ActorID:        identity.OwnerAccountID,
				ActorName:      "owner@example.test",
				Authentication: "password_passkey",
				SourceIP:       "192.0.2.30",
			},
		),
	)
	confirmed := httptest.NewRecorder()

	auth.Handler().ServeHTTP(confirmed, request)

	if confirmed.Code != http.StatusNoContent {
		t.Fatal("setup confirmation failed", confirmed.Code)
	}

	event := audit.PublicEvent(sink.event)

	if event.Action != "admin.account_activated" || event.ActorType != "unknown" ||
		event.ActorID != "" ||
		event.TargetID != "invited" ||
		event.Metadata["target_name"] != "invited@example.test" ||
		event.Metadata["auth_method"] != "password_totp" ||
		event.Metadata["source_ip"] != "192.0.2.30" {
		t.Fatal("setup activity borrowed owner authority or lost its actual target")
	}
}

func TestInvitationHTTPNeverUsesInputEmailAsAccountAuthority(t *testing.T) {
	auth, store := mailAuthFixture(t)

	now := time.Unix(2000000000, 0).UTC()

	store.SetAccountForTest(
		identity.Account{
			ID:              "another",
			Email:           "other@example.test",
			Role:            identity.RoleAdmin,
			Status:          identity.AccountInvited,
			AuthVersion:     3,
			PasswordHash:    fixturePasswordHash(t),
			UserHandle:      []byte("other-user"),
			EmailVerifiedAt: &now,
		},
	)
	origin := "https://home.example.test"

	mismatch := mailRequest(
		t,
		auth,
		"/invitation/accept",
		`{"email":"other@example.test","token":"private-token","password":"private long password"}`,
		origin,
	)

	if mismatch.Code != http.StatusAccepted {
		t.Fatal("committed invitation mismatch did not direct to resumable setup", mismatch.Code)
	}

	for _, cookie := range mismatch.Result().Cookies() {
		if cookie.Name == enrollmentCookieName && cookie.Value != "" && cookie.MaxAge >= 0 {
			t.Fatal("input email selected setup authority")
		}
	}

	accepted := mailRequest(
		t,
		auth,
		"/invitation/accept",
		`{"email":"Invited@Example.Test","token":"private-token","password":"private long password"}`,
		origin,
	)

	if accepted.Code != http.StatusOK {
		t.Fatal("canonical invited address did not continue setup", accepted.Code)
	}

	cookie := proofCookie(t, accepted, enrollmentCookieName)
	context, err := auth.enrollment.Context(t.Context(), cookie.Value)

	if err != nil || context.AccountID != "invited" {
		t.Fatal("accepted invitation setup belongs to another account", err)
	}
}
