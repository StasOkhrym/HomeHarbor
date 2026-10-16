package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestHomeownerNavigationHasSixDestinationsAndContextualSections(t *testing.T) {
	want := []string{
		"/admin/",
		"/admin/devices",
		"/admin/services",
		"/admin/connections",
		"/admin/activity",
		"/admin/settings",
	}

	navPattern := regexp.MustCompile(`(?s)<nav class="nav-list".*?</nav>`)

	linkPattern := regexp.MustCompile(`<a href="([^"]+)"`)
	for _, page := range []string{"overview", "devices", "invites", "services", "connections", "activity", "settings", "access", "network", "security", "setup"} {
		t.Run(page, func(t *testing.T) {
			response := httptest.NewRecorder()

			RenderPage(
				response,
				http.StatusOK,
				NewPage(page, "csrf", ""),
				slog.New(slog.NewTextHandler(io.Discard, nil)),
			)

			if response.Code != http.StatusOK {
				t.Fatalf("render status %d", response.Code)
			}

			primary := strings.Join(
				strings.Fields(navPattern.FindString(response.Body.String())),
				" ",
			)
			var destinations []string
			for _, link := range linkPattern.FindAllStringSubmatch(primary, -1) {
				destinations = append(destinations, link[1])
			}

			if !reflect.DeepEqual(destinations, want) {
				t.Fatalf("primary destinations = %v", destinations)
			}
			if page == "invites" &&
				!strings.Contains(primary, `href="/admin/devices" aria-current="page"`) {
				t.Fatal("invites lost device navigation context")
			}

			if page == "settings" || page == "access" || page == "network" || page == "security" ||
				page == "setup" {
				if !strings.Contains(primary, `href="/admin/settings" aria-current="page"`) {
					t.Fatal("settings section lost active context")
				}

				for _, path := range []string{"/admin/access", "/admin/network", "/admin/security", "/admin/setup"} {
					if !strings.Contains(response.Body.String(), `href="`+path+`"`) {
						t.Fatalf("missing contextual settings destination %s", path)
					}
				}
			}
		})
	}
}
