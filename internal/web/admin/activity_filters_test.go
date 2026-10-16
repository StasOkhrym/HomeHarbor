package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

// Ignoring unknown filters must not turn a narrowed audit query into all events.
func TestActivityFilterValidation(t *testing.T) {
	for _, raw := range []string{"category=not-a-category", "outcome=maybe", "period=forever"} {
		t.Run(raw, func(t *testing.T) {
			values, err := url.ParseQuery(raw)
			if err != nil {
				t.Fatal(err)
			}

			reader := &fragmentActivityReader{}

			view, status := LoadActivity(t.Context(), reader, values)

			if status != http.StatusBadRequest || reader.calls != 0 || view.Error == "" {
				t.Fatalf(
					"invalid filter status=%d calls=%d error=%q",
					status,
					reader.calls,
					view.Error,
				)
			}
		})
	}
}

// Filtering/history must remain usable without memorizing internal action IDs.
func TestActivityFiltersUseDropdownsAndPreserveSelection(t *testing.T) {
	values := url.Values{
		"category":  {"devices"},
		"action":    {"device.revoked"},
		"outcome":   {"failure"},
		"period":    {"7d"},
		"limit":     {"1"},
		"before_id": {"100"},
	}

	view, status := LoadActivity(t.Context(), &fragmentActivityReader{}, values)

	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}

	model := NewPage("activity", "", "")
	model.Activity = view
	response := httptest.NewRecorder()

	RenderPage(response, status, model, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if response.Code != http.StatusOK {
		t.Fatalf("render status=%d", response.Code)
	}

	root, err := html.Parse(strings.NewReader(response.Body.String()))
	if err != nil {
		t.Fatal(err)
	}

	for name, value := range map[string]string{"category": "devices", "action": "device.revoked", "outcome": "failure", "period": "7d"} {
		selectNode := findActivityNode(root, func(n *html.Node) bool {
			return n.Type == html.ElementNode && n.Data == "select" &&
				activityAttribute(n, "name") == name
		})
		if selectNode == nil {
			t.Errorf("missing accessible dropdown for %s", name)

			continue
		}

		selected := findActivityNode(selectNode, func(n *html.Node) bool {
			if n.Type != html.ElementNode || n.Data != "option" ||
				activityAttribute(n, "value") != value {
				return false
			}

			for _, attr := range n.Attr {
				if attr.Key == "selected" {
					return true
				}
			}

			return false
		})

		if selected == nil {
			t.Errorf("dropdown %s did not retain %q", name, value)
		}

		id := activityAttribute(selectNode, "id")

		label := findActivityNode(root, func(n *html.Node) bool {
			return n.Type == html.ElementNode && n.Data == "label" && id != "" &&
				activityAttribute(n, "for") == id
		})

		if label == nil {
			t.Errorf("dropdown %s has no explicit label", name)
		}
	}

	link := findActivityNode(root, func(n *html.Node) bool {
		if n.Type != html.ElementNode || n.Data != "a" {
			return false
		}

		u, e := url.Parse(activityAttribute(n, "href"))

		return e == nil && u.Path == "/admin/activity" && u.Query().Get("before_id") == "7"
	})

	if link == nil {
		t.Fatal("missing older-events cursor")
	}

	u, _ := url.Parse(activityAttribute(link, "href"))
	for _, key := range []string{"category", "action", "outcome", "period"} {
		if u.Query().Get(key) != values.Get(key) {
			t.Errorf("older events lost %s", key)
		}
	}
}

func findActivityNode(n *html.Node, match func(*html.Node) bool) *html.Node {
	if match(n) {
		return n
	}

	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if found := findActivityNode(child, match); found != nil {
			return found
		}
	}

	return nil
}

func activityAttribute(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}

	return ""
}

func TestActivityPeriodUsesUTCBounds(t *testing.T) {
	now := time.Date(2026, 10, 16, 14, 30, 0, 0, time.FixedZone("local", 3*60*60))
	reader := &fragmentActivityReader{}

	_, status := loadActivity(
		t.Context(),
		reader,
		url.Values{
			"period":    {"24h"},
			"category":  {"devices"},
			"outcome":   {"success"},
			"actor_id":  {"owner"},
			"device_id": {"phone"},
		},
		now,
	)
	want := time.Date(2026, 10, 15, 11, 30, 0, 0, time.UTC)

	if status != http.StatusOK || !reader.query.Since.Equal(want) ||
		!reader.query.Until.Equal(time.Date(2026, 10, 16, 11, 30, 0, 0, time.UTC)) ||
		reader.query.Category != "devices" ||
		reader.query.Outcome != "success" ||
		reader.query.ActorID != "owner" ||
		reader.query.DeviceID != "phone" {
		t.Fatalf("period status=%d query=%+v", status, reader.query)
	}
}
