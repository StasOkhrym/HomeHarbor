package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestMailPagesDoNotConsumeLinkProofOrOfferRegistration(t *testing.T) {
	auth, _ := mailAuthFixture(t)
	auth.emailEnabled = true
	for _, tc := range []struct{ path, title string }{
		{"/admin/invitation", "Set up your admin account"},
		{"/admin/reset-password", "Reset your password"},
		{"/admin/verify-email", "Confirm your email"},
		{"/admin/complete-account", "Finish your account setup"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()

			auth.LoginHandler().
				ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.path+"?token=PRIVATE_QUERY_TOKEN", nil))
			body := response.Body.String()

			if response.Code != http.StatusOK || !strings.Contains(body, tc.title) ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("dedicated safe mail page unavailable", response.Code)
			}

			for _, forbidden := range []string{"PRIVATE_QUERY_TOKEN", `name="token"`, "Create owner passkey", "Sign up with Google"} {
				if strings.Contains(body, forbidden) {
					t.Fatal("public mail page exposed proof or registration")
				}
			}

			if !strings.Contains(body, "<fieldset disabled") ||
				!strings.Contains(body, `method="post"`) {
				t.Fatal("secret forms were not safely intercepted before entry")
			}

			noAdminCookie(t, response)
		})
	}
}

func TestMailSetupPageReadsProofWithoutStartingMFA(t *testing.T) {
	auth, store := mailAuthFixture(t)
	origin := "https://home.example.test"

	password := mailRequest(
		t,
		auth,
		"/enrollment/password",
		`{"email":"invited@example.test","password":"private long password"}`,
		origin,
	)

	cookie := proofCookie(t, password, enrollmentCookieName)

	before := store.CeremonyCount()
	for range 5 {
		request := httptest.NewRequest(http.MethodGet, "/admin/complete-account", nil)

		request.AddCookie(cookie)
		response := httptest.NewRecorder()

		auth.LoginHandler().ServeHTTP(response, request)

		if response.Code != http.StatusOK ||
			!strings.Contains(response.Body.String(), "Protect your account") ||
			strings.Contains(response.Body.String(), cookie.Value) ||
			strings.Contains(response.Body.String(), "otpauth://") {
			t.Fatal("setup render exposed or consumed proof", response.Code)
		}
	}

	if store.CeremonyCount() != before {
		t.Fatal("GET started a passkey ceremony")
	}

	if _, err := store.TOTP(
		t.Context(),
		"invited",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("GET generated a private TOTP seed", err)
	}
}
