package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

type contextualActivityReader struct{ facetCalls int }

func (*contextualActivityReader) ListRecords(context.Context, audit.Query) ([]audit.Record, error) {
	return []audit.Record{
		{
			RecordID: 7,
			Event: audit.Event{
				Action:     "device.revoked",
				ActorType:  "admin",
				ActorID:    "a-1",
				TargetType: "device",
				TargetID:   "d-1",
				Metadata: map[string]any{
					"actor_name":      "Olena",
					"target_name":     "Kitchen Mac",
					"source_ip":       "192.0.2.9",
					"device_platform": "macos",
					"os_version":      "15.0",
					"client_version":  "0.1.0",
					"overlay_ip":      "10.243.0.1",
					"authorization":   "SECRET_TOKEN",
				},
			},
		},
	}, nil
}

func (r *contextualActivityReader) ListFacets(context.Context) (audit.Facets, error) {
	r.facetCalls++
	return audit.Facets{
		Actors:  []audit.Facet{{ID: "a-1", Name: "Olena"}},
		Devices: []audit.Facet{{ID: "d-1", Name: "Kitchen Mac"}},
	}, nil
}

func TestActivityMetadataAndNamedIdentityDropdowns(t *testing.T) {
	reader := &contextualActivityReader{}

	view, status := LoadActivity(
		t.Context(),
		reader,
		url.Values{"actor_id": {"a-1"}, "device_id": {"d-1"}},
	)
	model := NewPage("activity", "", "")
	model.Activity = view
	response := httptest.NewRecorder()

	RenderPage(response, status, model, slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := response.Body.String()
	for _, want := range []string{"Olena", "Kitchen Mac", "HTTP source IP", "192.0.2.9", "Overlay IP", "10.243.0.1", "15.0", "0.1.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}

	if strings.Contains(body, "SECRET_TOKEN") || reader.facetCalls != 1 {
		t.Fatalf("unsafe metadata/facet calls=%d", reader.facetCalls)
	}

	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	for name, id := range map[string]string{"actor_id": "a-1", "device_id": "d-1"} {
		selectNode := findActivityNode(root, func(n *html.Node) bool {
			return n.Type == html.ElementNode && n.Data == "select" &&
				activityAttribute(n, "name") == name
		})
		if selectNode == nil {
			t.Errorf("missing %s dropdown", name)

			continue
		}

		selected := findActivityNode(
			selectNode,
			func(n *html.Node) bool { return n.Data == "option" && activityAttribute(n, "value") == id },
		)

		if selected == nil {
			t.Errorf("missing %s identity option", name)
		}
	}
}

func TestActivityPollingDoesNotReloadFilterFacets(t *testing.T) {
	reader := &contextualActivityReader{}
	response := httptest.NewRecorder()

	ActivityFragment(
		reader,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	).ServeHTTP(response, httptest.NewRequest("GET", "/admin/activity/fragment", nil))

	if response.Code != 200 || reader.facetCalls != 0 ||
		!strings.Contains(response.Body.String(), "Kitchen Mac") {
		t.Fatalf("poll status=%d facet calls=%d", response.Code, reader.facetCalls)
	}
}
