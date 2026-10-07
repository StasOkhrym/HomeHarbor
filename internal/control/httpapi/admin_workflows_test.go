package httpapi

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/policy"
	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
	memorydevices "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
	memorypolicy "github.com/StasOkhrym/homeharbor/internal/testutil/control/policy"
	memoryroutes "github.com/StasOkhrym/homeharbor/internal/testutil/control/routes"
	memoryservices "github.com/StasOkhrym/homeharbor/internal/testutil/control/services"
)

func postAdminForm(
	handler http.Handler,
	path string,
	values url.Values,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	return response
}

func TestAdminServiceFormGeneratesID(t *testing.T) {
	catalog := controlservices.NewService(memoryservices.NewRepository(), time.Now)

	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Services: catalog}},
	).Handler()

	response := postAdminForm(handler, "/admin/services", url.Values{
		"name": {"Photos"}, "kind": {"web"}, "url": {"https://photos.home.arpa"},
	})

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	items, _ := catalog.List(context.Background())

	if len(items) != 1 || items[0].ID == "" || items[0].Name != "Photos" {
		t.Fatalf("saved service=%v", items)
	}
}

func TestAdminServiceErrorPreservesEscapedValues(t *testing.T) {
	catalog := controlservices.NewService(memoryservices.NewRepository(), time.Now)
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Services: catalog}},
	).Handler()
	response := postAdminForm(handler, "/admin/services", url.Values{
		"name": {
			`<script>alert('x')</script>`,
		},
		"kind": {"web"},
		"url":  {"http://not-https.example"},
	})
	body := response.Body.String()
	if response.Code != http.StatusBadRequest || !strings.Contains(body, "&lt;script&gt;") ||
		!strings.Contains(body, `aria-invalid="true"`) {
		t.Fatalf("form error lost values or field state: status=%d body=%s", response.Code, body)
	}
	if strings.Contains(body, `<script>alert('x')</script>`) {
		t.Fatal("unescaped submitted name")
	}
	items, _ := catalog.List(context.Background())
	if len(items) != 0 {
		t.Fatal("invalid form persisted a service")
	}
}

func TestAdminMissingServiceRejectsPostWithoutPanic(t *testing.T) {
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{},
	).Handler()

	response := postAdminForm(handler, "/admin/services", url.Values{"name": {"Photos"}})

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing service status=%d", response.Code)
	}
}

func TestAdminPolicyPreviewDoesNotPersist(t *testing.T) {
	service := policy.NewService(memorypolicy.NewRepository(), acl.Compiler{})
	auth, _ := newBrowserAuthTest(t)
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{Policy: service},
			Browser:   BrowserDependencies{ActionConfirmation: auth},
		},
	).Handler()
	response := postAdminForm(handler, "/admin/policy/preview", url.Values{
		"rules": {
			`[{"id":"ssh","source_device_id":"client-a","destination":"192.168.50.0/24","protocol":"tcp","port_from":22,"port_to":22}]`,
		},
	})
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "Review policy replacement") {
		t.Fatalf("preview status=%d body=%s", response.Code, response.Body.String())
	}
	value, _ := service.Latest(context.Background())
	if value.Revision != 0 || len(value.Rules) != 0 {
		t.Fatal("preview mutated policy")
	}
}

func TestAdminPolicyRequiresConfirmation(t *testing.T) {
	service := policy.NewService(memorypolicy.NewRepository(), acl.Compiler{})
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Policy: service}},
	).Handler()
	response := postAdminForm(handler, "/admin/policy", url.Values{"rules": {"[]"}})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed replacement status=%d", response.Code)
	}
	value, _ := service.Latest(context.Background())
	if value.Revision != 0 {
		t.Fatal("unconfirmed replacement persisted")
	}
}

func htmlInput(t *testing.T, body, name string) string {
	t.Helper()
	match := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `"\s+value="([^"]*)"`).
		FindStringSubmatch(body)

	if len(match) != 2 {
		t.Fatalf("missing input %s", name)
	}

	return match[1]
}

func TestAdminFormIDSurvivesRetry(t *testing.T) {
	catalog := controlservices.NewService(memoryservices.NewRepository(), time.Now)

	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Services: catalog}},
	).Handler()
	page := httptest.NewRecorder()

	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/admin/services", nil))
	id := htmlInput(t, page.Body.String(), "id")
	values := url.Values{
		"id":   {id},
		"name": {"Photos"},
		"kind": {"web"},
		"url":  {"https://photos.home.arpa"},
	}
	if got := postAdminForm(handler, "/admin/services", values).Code; got != http.StatusSeeOther {
		t.Fatalf("first status=%d", got)
	}

	if got := postAdminForm(handler, "/admin/services", values).Code; got != http.StatusConflict {
		t.Fatalf("retry status=%d", got)
	}

	items, _ := catalog.List(context.Background())

	if len(items) != 1 {
		t.Fatalf("retry duplicated service: %v", items)
	}
}

func TestAdminServiceInvalidURLIsFieldError(t *testing.T) {
	catalog := controlservices.NewService(memoryservices.NewRepository(), time.Now)
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Services: catalog}},
	).Handler()
	for _, value := range []string{"https://user:secret@example.com", "https://example.com/#fragment", "javascript://example.com"} {
		response := postAdminForm(handler, "/admin/services", url.Values{
			"name": {"Photos"}, "kind": {"web"}, "url": {value},
		})
		if response.Code != http.StatusBadRequest {
			t.Errorf("URL %q status=%d", value, response.Code)
		}
	}
}

func TestAdminPolicyPreviewRoundTripAndReplay(t *testing.T) {
	service := policy.NewService(memorypolicy.NewRepository(), acl.Compiler{})
	auth, _ := newBrowserAuthTest(t)
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{Policy: service},
			Browser:   BrowserDependencies{ActionConfirmation: auth},
		},
	).Handler()
	preview := postAdminForm(handler, "/admin/policy/preview", url.Values{
		"editor":           {"structured"},
		"rule_id":          {"ssh"},
		"source_device_id": {"client-a"},
		"destination": {
			"192.168.50.12/24",
		},
		"protocol":  {"tcp"},
		"port_from": {"22"},
		"port_to":   {"22"},
	})
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d", preview.Code)
	}
	if !strings.Contains(preview.Body.String(), "Added") {
		t.Fatal("preview has no added-rule diff")
	}
	values := url.Values{
		"confirmed": {"yes"}, "revision": {htmlInput(t, preview.Body.String(), "revision")},
		"proof": {htmlInput(t, preview.Body.String(), "proof")},
		"rules": {html.UnescapeString(htmlInput(t, preview.Body.String(), "rules"))},
	}
	if got := postAdminForm(handler, "/admin/policy", values).Code; got != http.StatusSeeOther {
		t.Fatalf("confirmed status=%d", got)
	}
	value, _ := service.Latest(context.Background())
	if value.Revision != 1 || len(value.Rules) != 1 ||
		value.Rules[0].Destination.String() != "192.168.50.0/24" {
		t.Fatalf("round-trip policy=%v", value)
	}
	if got := postAdminForm(handler, "/admin/policy", values).Code; got != http.StatusConflict {
		t.Fatalf("replay status=%d", got)
	}
}

func TestAdminPolicyRejectsTamperedConfirmation(t *testing.T) {
	service := policy.NewService(memorypolicy.NewRepository(), acl.Compiler{})
	auth, _ := newBrowserAuthTest(t)
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{Policy: service},
			Browser:   BrowserDependencies{ActionConfirmation: auth},
		},
	).Handler()
	preview := postAdminForm(handler, "/admin/policy/preview", url.Values{"rules": {"[]"}})
	proof := htmlInput(t, preview.Body.String(), "proof")
	response := postAdminForm(handler, "/admin/policy", url.Values{
		"confirmed": {"yes"},
		"revision":  {"0"},
		"proof":     {proof},
		"rules": {
			`[{"id":"ssh","source_device_id":"client-a","destination":"192.168.50.0/24","protocol":"tcp","port_from":22,"port_to":22}]`,
		},
	})
	if response.Code != http.StatusForbidden {
		t.Fatalf("tampered status=%d", response.Code)
	}
	value, _ := service.Latest(context.Background())
	if value.Revision != 0 {
		t.Fatal("tampered preview was saved")
	}
}

func TestBrowserConfirmationBindsSessionAndAction(t *testing.T) {
	auth, _ := newBrowserAuthTest(t)

	proof := auth.SignAction("csrf-a", []byte("action-a"))

	if !auth.VerifyAction("csrf-a", []byte("action-a"), proof) ||
		auth.VerifyAction("csrf-b", []byte("action-a"), proof) ||
		auth.VerifyAction("csrf-a", []byte("action-b"), proof) {
		t.Fatal("confirmation is not scoped")
	}
}

func TestAdminStructuredPolicyPreservesInvalidRow(t *testing.T) {
	service := policy.NewService(memorypolicy.NewRepository(), acl.Compiler{})
	auth, _ := newBrowserAuthTest(t)
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{Policy: service},
			Browser:   BrowserDependencies{ActionConfirmation: auth},
		},
	).Handler()
	response := postAdminForm(handler, "/admin/policy/preview", url.Values{
		"editor": {"structured"}, "rule_id": {"ssh"}, "source_device_id": {"client-a"},
		"destination": {"not-a-cidr"}, "protocol": {"tcp"}, "port_from": {"22"}, "port_to": {"22"},
	})
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), `value="not-a-cidr"`) {
		t.Fatal("invalid structured row was lost")
	}
}

func TestAdminPolicyDiffIncludesRemovalAndModification(t *testing.T) {
	service := policy.NewService(memorypolicy.NewRepository(), acl.Compiler{})
	var rules []acl.Rule
	if err := json.Unmarshal(
		[]byte(
			`[{"id":"ssh","source_device_id":"client-a","destination":"192.168.50.0/24","protocol":"tcp","port_from":22,"port_to":22}]`,
		),
		&rules,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Replace(context.Background(), rules); err != nil {
		t.Fatal(err)
	}
	auth, _ := newBrowserAuthTest(t)
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{Policy: service},
			Browser:   BrowserDependencies{ActionConfirmation: auth},
		},
	).Handler()
	for _, test := range []struct{ rules, label string }{
		{"[]", "Removed"},
		{`[{"id":"ssh","source_device_id":"client-a","destination":"192.168.50.0/24","protocol":"tcp","port_from":443,"port_to":443}]`, "Modified"},
	} {
		response := postAdminForm(
			handler,
			"/admin/policy/preview",
			url.Values{"rules": {test.rules}},
		)
		if !strings.Contains(response.Body.String(), test.label) {
			t.Errorf("missing %s diff", test.label)
		}
	}
}

func TestAdminProfileSelectionsPersistAfterError(t *testing.T) {
	catalog := controlservices.NewService(memoryservices.NewRepository(), time.Now)
	for _, id := range []string{"photos", "cloud"} {
		if _, err := catalog.Create(
			context.Background(),
			controlservices.Service{
				ID:   id,
				Name: id,
				Kind: controlservices.KindWeb,
				URL:  "https://" + id + ".home.arpa",
			},
		); err != nil {
			t.Fatal(err)
		}
	}
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Services: catalog}},
	).Handler()
	response := postAdminForm(
		handler,
		"/admin/access-profiles",
		url.Values{"name": {""}, "service_ids": {"photos", "cloud"}},
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
	for _, id := range []string{"photos", "cloud"} {
		if !regexp.MustCompile(`value="` + regexp.QuoteMeta(id) + `"\s+checked`).
			MatchString(response.Body.String()) {
			t.Errorf("selection %s lost", id)
		}
	}
}

func TestAdminTokenValidationRetainsRole(t *testing.T) {
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{},
	).Handler()
	response := postAdminForm(
		handler,
		"/admin/enrollment-tokens",
		url.Values{"role": {"gateway"}, "ttl_seconds": {"9223372036854775807"}},
	)
	if response.Code != http.StatusBadRequest ||
		!regexp.MustCompile(`value="gateway"\s+selected`).MatchString(response.Body.String()) {
		t.Fatal("token validation lost chosen role or accepted overflow")
	}
}

func TestAdminTokenPageIsOneTimeAndNoStore(t *testing.T) {
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{},
	).Handler()

	response := postAdminForm(
		handler,
		"/admin/enrollment-tokens",
		url.Values{"role": {"client"}, "ttl_seconds": {"600"}},
	)

	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(
			response.Body.String(),
			"data-secret-page",
		) || !strings.Contains(response.Body.String(), "/assets/admin.js") {
		t.Fatal("token page lacks one-time browser lifecycle or no-store")
	}
}

func TestAdminRejectsUnsafeBrowserID(t *testing.T) {
	catalog := controlservices.NewService(memoryservices.NewRepository(), time.Now)
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Services: catalog}},
	).Handler()
	response := postAdminForm(
		handler,
		"/admin/services",
		url.Values{
			"id":   {"../bad"},
			"name": {"Photos"},
			"kind": {"web"},
			"url":  {"https://photos.home.arpa"},
		},
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unsafe ID status=%d", response.Code)
	}
}

func TestAdminNetworkSupportsBothApprovalTransitions(t *testing.T) {
	service := controlroutes.NewService(memoryroutes.NewRepository(), time.Now)

	_, err := service.Advertise(context.Background(), controlroutes.AdvertisementRequest{
		ID: "home", GatewayDeviceID: "gateway", Prefix: netip.MustParsePrefix("192.168.50.0/24"),
		Resolver: netip.MustParseAddr("192.168.50.1"), DomainSuffix: "home.arpa",
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Routes: service}},
	).Handler()
	for _, action := range []string{"approve", "reject", "approve"} {
		page := httptest.NewRecorder()

		handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/admin/network", nil))

		if !strings.Contains(page.Body.String(), `action="/admin/routes/`+action+`"`) ||
			!strings.Contains(page.Body.String(), `name="route_id" value="home"`) {
			t.Fatalf("missing %s action", action)
		}

		if got := postAdminForm(
			handler,
			"/admin/routes/home/"+action,
			url.Values{"return_to": {"network"}},
		).Code; got != http.StatusSeeOther {
			t.Fatalf("%s status=%d", action, got)
		}
	}
}

func TestAdminErrorDoesNotRetainURLCredentials(t *testing.T) {
	catalog := controlservices.NewService(memoryservices.NewRepository(), time.Now)
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Services: catalog}},
	).Handler()
	response := postAdminForm(
		handler,
		"/admin/services",
		url.Values{
			"name": {"Photos"},
			"kind": {"web"},
			"url":  {"https://user:never-retain-this@example.com"},
		},
	)
	if response.Code != http.StatusBadRequest ||
		strings.Contains(response.Body.String(), "never-retain-this") {
		t.Fatal("validation retained URL credentials")
	}
}
