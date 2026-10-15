package httpapi

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	memorydevices "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
)

func TestServedBrowserFormPreservesOriginAndRequiresCSRF(t *testing.T) {
	for _, scenario := range []string{"valid", "missing-csrf", "wrong-csrf", "foreign-origin", "null-origin", "missing-origin", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			auth, sessions := newBrowserAuthTest(t)

			csrf, err := browserCSRFCookie(t, sessions.session)
			if err != nil {
				t.Fatal(err)
			}

			handler := newTestServer(
				devices.NewService(memorydevices.NewRepository(), time.Now, nil),
				auth,
				Dependencies{
					Browser: BrowserDependencies{MutationAuthorizer: auth.AuthorizeMutation},
				},
				auth,
			).Handler()
			read := httptest.NewRequest(
				http.MethodGet,
				"https://tunnel.example.com/admin/invites",
				nil,
			)

			read.AddCookie(browserSessionCookie(t, sessions.session))
			read.AddCookie(csrf)
			page := httptest.NewRecorder()

			handler.ServeHTTP(page, read)

			if page.Code != http.StatusOK {
				t.Fatalf("invites status=%d", page.Code)
			}

			field := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).
				FindStringSubmatch(page.Body.String())

			if len(field) != 2 {
				t.Fatal("rendered form has no CSRF proof")
			}

			// WHATWG Fetch's append-a-request-Origin-header algorithm for an
			// ordinary HTTPS same-origin form POST. Unlike fetch's CORS mode,
			// navigate mode serializes the origin as null under no-referrer.
			// https://fetch.spec.whatwg.org/#append-a-request-origin-header
			origins := map[string]string{
				"no-referrer":                     "null",
				"same-origin":                     "https://tunnel.example.com",
				"origin":                          "https://tunnel.example.com",
				"origin-when-cross-origin":        "https://tunnel.example.com",
				"strict-origin":                   "https://tunnel.example.com",
				"strict-origin-when-cross-origin": "https://tunnel.example.com",
				"no-referrer-when-downgrade":      "https://tunnel.example.com",
			}
			origin, known := origins[page.Header().Get("Referrer-Policy")]
			if !known {
				t.Fatal("form response has an uncharacterized referrer policy")
			}

			values := url.Values{
				"role":        {"gateway"},
				"ttl_seconds": {"600"},
				"_csrf":       {html.UnescapeString(field[1])},
			}
			want := http.StatusUnauthorized
			switch scenario {
			case "valid":
				want = http.StatusOK
			case "missing-csrf":
				values.Del("_csrf")
			case "wrong-csrf":
				values.Set("_csrf", "wrong")
			case "foreign-origin":
				origin = "https://attacker.example"
			case "null-origin":
				origin = "null"
			case "missing-origin":
				origin = ""
			case "expired":
				sessions.session.ExpiresAt = time.Now().Add(-time.Minute)
			}

			write := httptest.NewRequest(
				http.MethodPost,
				"https://tunnel.example.com/admin/enrollment-tokens",
				strings.NewReader(values.Encode()),
			)
			write.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			write.Header.Set("Origin", origin)
			write.AddCookie(browserSessionCookie(t, sessions.session))
			write.AddCookie(csrf)
			result := httptest.NewRecorder()

			handler.ServeHTTP(result, write)

			if result.Code != want {
				t.Fatalf(
					"form POST status=%d want=%d (served policy=%q, browser origin=%q)",
					result.Code,
					want,
					page.Header().Get("Referrer-Policy"),
					origin,
				)
			}
			if scenario == "valid" &&
				(!strings.Contains(result.Body.String(), "data-secret-page") || result.Header().Get("Cache-Control") != "no-store" || result.Header().Get("Referrer-Policy") != "no-referrer") {
				t.Fatal("successful enrollment did not produce the protected one-time page")
			}
		})
	}
}
