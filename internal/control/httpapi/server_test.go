package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sokhrym/go-tunnels/internal/control/audit"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	controlroutes "github.com/sokhrym/go-tunnels/internal/control/routes"
	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
	controlsnapshots "github.com/sokhrym/go-tunnels/internal/control/snapshots"
	"github.com/sokhrym/go-tunnels/internal/invite"
	"github.com/sokhrym/go-tunnels/internal/protocol"
	"github.com/sokhrym/go-tunnels/internal/relay"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

func TestEnrollmentAPIRequiresAdminAndEnrollsDevice(t *testing.T) {
	deviceService := devices.NewService(devices.NewMemoryStore(), time.Now, nil)
	handler := newTestServer(deviceService, headerAuthorizer{}).Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-tokens", bytes.NewBufferString(`{"role":"client","ttl_seconds":3600}`)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	issueRequest := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-tokens", bytes.NewBufferString(`{"role":"client","ttl_seconds":3600}`))
	issueRequest.Header.Set("X-Test-Admin", "true")
	issued := httptest.NewRecorder()
	handler.ServeHTTP(issued, issueRequest)
	if issued.Code != http.StatusCreated {
		t.Fatalf("issue status = %d body=%s", issued.Code, issued.Body.String())
	}
	var token devices.IssuedToken
	if err := json.NewDecoder(issued.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(validEnrollmentRequest(t, token.Token, "laptop"))
	enrolled := httptest.NewRecorder()
	handler.ServeHTTP(enrolled, httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body)))
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d body=%s", enrolled.Code, enrolled.Body.String())
	}
	var enrolledDevice devices.Device
	if err := json.NewDecoder(enrolled.Body).Decode(&enrolledDevice); err != nil {
		t.Fatal(err)
	}
	rotateRequest := httptest.NewRequest(http.MethodPost, "/api/v1/devices/credentials/rotate", nil)
	rotateRequest.Header.Set("Authorization", "Bearer "+enrolledDevice.Credential)
	rotated := httptest.NewRecorder()
	handler.ServeHTTP(rotated, rotateRequest)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate status = %d body=%s", rotated.Code, rotated.Body.String())
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	listRequest.Header.Set("X-Test-Admin", "true")
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, listRequest)
	if listed.Code != http.StatusOK {
		t.Fatalf("list status = %d", listed.Code)
	}
}

func TestRelaySessionAPIRequiresDeviceAuthenticationAndActivePeer(t *testing.T) {
	deviceService := devices.NewService(devices.NewMemoryStore(), time.Now, nil)
	tokenA, err := deviceService.IssueEnrollmentToken(context.Background(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deviceA, err := deviceService.Enroll(context.Background(), validEnrollmentRequest(t, tokenA.Token, "a"))
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := deviceService.IssueEnrollmentToken(context.Background(), devices.RoleGateway, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deviceB, err := deviceService.Enroll(context.Background(), validEnrollmentRequest(t, tokenB.Token, "b"))
	if err != nil {
		t.Fatal(err)
	}
	issuer := relay.TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	handler := newTestServer(deviceService, allowAuthorizer{}, WithRelaySessionIssuer(issuer, "wss://relay.example.com/relay/udp/v2", time.Minute)).Handler()

	request := httptest.NewRequest(http.MethodPost, "/api/v1/relay-sessions", bytes.NewBufferString(`{"session_id":"session-1","destination_device_id":"`+deviceB.ID+`","capabilities":["udp_pair_v2"]}`))
	request.Header.Set("Authorization", "Bearer "+deviceA.Credential)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		RelayURL        string `json:"relay_url"`
		RelayUDPAddress string `json:"relay_udp_address"`
		Ticket          string `json:"ticket"`
		RelayTransport  string `json:"relay_transport"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.RelayURL != "wss://relay.example.com/relay/udp/v2" || response.RelayUDPAddress != "" || response.RelayTransport != "udp_pair_v2" || response.Ticket == "" {
		t.Fatalf("incomplete relay response=%#v", response)
	}
	if claims, err := issuer.Verify(response.Ticket); err != nil || claims.DeviceID != deviceA.ID {
		t.Fatalf("ticket claims=%#v error=%v", claims, err)
	}
	legacy := httptest.NewRecorder()
	legacyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/relay-sessions", strings.NewReader(`{"session_id":"session-1","destination_device_id":"`+deviceB.ID+`"}`))
	legacyRequest.Header.Set("Authorization", "Bearer "+deviceA.Credential)
	handler.ServeHTTP(legacy, legacyRequest)
	if legacy.Code != http.StatusUpgradeRequired || !strings.Contains(legacy.Body.String(), protocol.ErrorUpgradeRequired) {
		t.Fatalf("legacy ingress advertised: %d %s", legacy.Code, legacy.Body.String())
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/relay-sessions", strings.NewReader(`{"session_id":"s","destination_device_id":"`+deviceB.ID+`"}`)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
}

func TestRelaySessionRejectsSameRolePeer(t *testing.T) {
	deviceService := devices.NewService(devices.NewMemoryStore(), time.Now, nil)
	firstToken, err := deviceService.IssueEnrollmentToken(context.Background(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	first, err := deviceService.Enroll(context.Background(), validEnrollmentRequest(t, firstToken.Token, "first"))
	if err != nil {
		t.Fatal(err)
	}
	secondToken, err := deviceService.IssueEnrollmentToken(context.Background(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := deviceService.Enroll(context.Background(), validEnrollmentRequest(t, secondToken.Token, "second"))
	if err != nil {
		t.Fatal(err)
	}
	issuer := relay.TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	handler := newTestServer(deviceService, allowAuthorizer{}, WithRelaySessionIssuer(issuer, "wss://relay.example.com/relay/v1", time.Minute)).Handler()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/relay-sessions", strings.NewReader(`{"session_id":"session-1","destination_device_id":"`+second.ID+`"}`))
	request.Header.Set("Authorization", "Bearer "+first.Credential)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("same-role relay status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRelaySessionUsesConfiguredPeerAuthorizer(t *testing.T) {
	deviceService := devices.NewService(devices.NewMemoryStore(), time.Now, nil)
	clientToken, err := deviceService.IssueEnrollmentToken(context.Background(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client, err := deviceService.Enroll(context.Background(), validEnrollmentRequest(t, clientToken.Token, "client"))
	if err != nil {
		t.Fatal(err)
	}
	gatewayToken, err := deviceService.IssueEnrollmentToken(context.Background(), devices.RoleGateway, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := deviceService.Enroll(context.Background(), validEnrollmentRequest(t, gatewayToken.Token, "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	issuer := relay.TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	handler := newTestServer(deviceService, allowAuthorizer{}, WithRelaySessionIssuer(issuer, "wss://relay.example.com/relay/v1", time.Minute), WithRelayPeerAuthorizer(func(context.Context, devices.Device, devices.Device) bool { return false })).Handler()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/relay-sessions", strings.NewReader(`{"session_id":"session-1","destination_device_id":"`+gateway.ID+`"}`))
	request.Header.Set("Authorization", "Bearer "+client.Credential)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unauthorized peer status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHealthEndpoints(t *testing.T) {
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}).Handler()
	for _, path := range []string{"/healthz", "/readyz"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, recorder.Code)
		}
	}
}

func TestReadinessAndSecurityHeaders(t *testing.T) {
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}, WithReadiness(func(context.Context) error {
		return errors.New("database unavailable")
	})).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status = %d", recorder.Code)
	}
	if recorder.Header().Get("Content-Security-Policy") == "" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers = %#v", recorder.Header())
	}
}

func TestDecodeJSONRejectsTrailingValues(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(`{"name":"ok"}{"name":"unexpected"}`))
	var value struct {
		Name string `json:"name"`
	}
	if decodeJSON(recorder, request, &value) {
		t.Fatal("decodeJSON accepted trailing JSON value")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAdminPageUsesLocalAssets(t *testing.T) {
	catalog := controlservices.NewService(controlservices.NewMemoryStore(), time.Now, controlservices.WithDeviceActiveChecker(func(_ context.Context, _ string) (bool, error) {
		return true, nil
	}))
	if _, err := catalog.Create(context.Background(), controlservices.Service{ID: "cloud", Name: "Nextcloud", Kind: controlservices.KindWeb, URL: "https://cloud.home.example.com", Description: "Family files"}); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.CreateProfile(context.Background(), controlservices.AccessProfile{ID: "family", Name: "Family", ServiceIDs: []string{"cloud"}}); err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}, WithServiceCatalog(catalog)).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "unpkg.com") || strings.Contains(body, "<style>") || !strings.Contains(body, "/assets/admin.css") || !strings.Contains(body, "Nextcloud") || !strings.Contains(body, "Family") {
		t.Fatalf("admin page assets are not local: %s", body)
	}
	if strings.Contains(body, "Add LAN route") {
		t.Fatal("admin page exposed a route action without the network module")
	}
	approve := httptest.NewRecorder()
	handler.ServeHTTP(approve, httptest.NewRequest(http.MethodPost, "/admin/routes/route-1/approve", nil))
	if approve.Code != http.StatusNotFound {
		t.Fatalf("route approval without network module status=%d", approve.Code)
	}
}

func TestAdminFormCreatesServiceThroughDomainCatalog(t *testing.T) {
	catalog := controlservices.NewService(controlservices.NewMemoryStore(), time.Now, controlservices.WithDeviceActiveChecker(func(_ context.Context, _ string) (bool, error) {
		return true, nil
	}))
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}, WithServiceCatalog(catalog)).Handler()
	form := url.Values{
		"id":          {"cloud"},
		"name":        {"Nextcloud"},
		"kind":        {"web"},
		"url":         {"https://cloud.home.example.com"},
		"description": {"Family files"},
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/services", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/admin/?notice=service-created" {
		t.Fatalf("form status=%d location=%q body=%s", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	items, err := catalog.List(context.Background())
	if err != nil || len(items) != 1 || items[0].ID != "cloud" {
		t.Fatalf("catalog items=%#v error=%v", items, err)
	}
}

func TestAdminFormCreatesRouteThroughNetworkService(t *testing.T) {
	routeService := controlroutes.NewService(controlroutes.NewMemoryStore(), time.Now)
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}, WithRouteService(routeService)).Handler()
	form := url.Values{
		"id":                {"home-lan"},
		"gateway_device_id": {"gateway-home"},
		"prefix":            {"192.168.50.0/24"},
		"resolver":          {"192.168.50.1"},
		"domain_suffix":     {"home.arpa"},
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/routes", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/admin/?notice=route-created" {
		t.Fatalf("form status=%d location=%q body=%s", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	items, err := routeService.List(context.Background())
	if err != nil || len(items) != 1 || items[0].ID != "home-lan" || items[0].Status != controlroutes.StatusPending {
		t.Fatalf("routes=%#v error=%v", items, err)
	}
}

func TestAvailableServicesRequireDeviceCredentialAndProfileMembership(t *testing.T) {
	deviceService := devices.NewService(devices.NewMemoryStore(), time.Now, nil)
	token, err := deviceService.IssueEnrollmentToken(context.Background(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	device, err := deviceService.Enroll(context.Background(), validEnrollmentRequest(t, token.Token, "phone"))
	if err != nil {
		t.Fatal(err)
	}
	catalog := controlservices.NewService(controlservices.NewMemoryStore(), time.Now, controlservices.WithDeviceActiveChecker(func(_ context.Context, _ string) (bool, error) {
		return true, nil
	}))
	if _, err := catalog.Create(context.Background(), controlservices.Service{ID: "cloud", Name: "Cloud", Kind: controlservices.KindWeb, URL: "https://cloud.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.CreateProfile(context.Background(), controlservices.AccessProfile{ID: "family", Name: "Family", DeviceIDs: []string{device.ID}, ServiceIDs: []string{"cloud"}}); err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(deviceService, allowAuthorizer{}, WithServiceCatalog(catalog)).Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/services/available", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/services/available", nil)
	request.Header.Set("Authorization", "Bearer "+device.Credential)
	available := httptest.NewRecorder()
	handler.ServeHTTP(available, request)
	if available.Code != http.StatusOK || !strings.Contains(available.Body.String(), `"id":"cloud"`) {
		t.Fatalf("available status=%d body=%s", available.Code, available.Body.String())
	}
}

func TestGroupedResourceRoutesKeepAdminBoundary(t *testing.T) {
	catalog := controlservices.NewService(controlservices.NewMemoryStore(), time.Now)
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), headerAuthorizer{}, WithServiceCatalog(catalog)).Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/admin/devices", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("grouped admin route status = %d", unauthorized.Code)
	}

	authorized := httptest.NewRequest(http.MethodGet, "/api/v1/admin/devices", nil)
	authorized.Header.Set("X-Test-Admin", "true")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, authorized)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "devices") {
		t.Fatalf("grouped device route status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	create := httptest.NewRequest(http.MethodPost, "/api/v1/services/", strings.NewReader(`{"id":"files","name":"Files","kind":"web","url":"https://files.home.example.com"}`))
	create.Header.Set("X-Test-Admin", "true")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, create)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("grouped service route status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAuditAPIRequiresAdminAndBoundsResults(t *testing.T) {
	reader := &auditReaderStub{events: []audit.Event{{
		OccurredAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		ActorType:  "device",
		ActorID:    "device-1",
		Action:     "device.revoked",
		TargetType: "device",
		TargetID:   "device-1",
		Metadata:   map[string]any{"reason": "test"},
	}}}
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), headerAuthorizer{}, WithAuditReader(reader)).Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized audit status = %d", unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit?limit=999", nil)
	request.Header.Set("X-Test-Admin", "true")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "device.revoked") {
		t.Fatalf("audit status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if reader.limit != 200 {
		t.Fatalf("audit reader limit = %d, want 200", reader.limit)
	}
}

func TestServiceCatalogAPIUsesAdminBoundary(t *testing.T) {
	catalog := controlservices.NewService(controlservices.NewMemoryStore(), time.Now)
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), headerAuthorizer{}, WithServiceCatalog(catalog)).Handler()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/services", bytes.NewBufferString(`{"id":"cloud","name":"Nextcloud","kind":"web","url":"https://cloud.home.example.com"}`))
	request.Header.Set("X-Test-Admin", "true")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create service status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/services", nil)
	request.Header.Set("X-Test-Admin", "true")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "cloud") {
		t.Fatalf("list service status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestInviteProofAPIDoesNotRequireAdmin(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	item, err := invite.New("home", "family", time.Minute, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := invite.SignPermit(item.Permit, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = devicePublic
	proof, err := item.Proof("device-1", devicePrivate, item.Code, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := controlinvites.NewService(controlinvites.NewMemoryStore(), rootPublic, "home", func() time.Time { return now })
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), headerAuthorizer{}, WithInviteService(service)).Handler()
	body, _ := json.Marshal(map[string]any{"permit": permit, "proof": proof})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/invites/proof", bytes.NewReader(body)))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("submit invite proof status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestClientKeyUsesForwardedAddressOnlyFromTrustedProxy(t *testing.T) {
	server := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}, WithTrustedProxyCIDRs([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}))
	trusted := httptest.NewRequest(http.MethodGet, "/", nil)
	trusted.RemoteAddr = "10.1.2.3:443"
	trusted.Header.Set("X-Forwarded-For", "192.0.2.10, 10.1.2.3")
	if got := server.clientKey(trusted); got != "192.0.2.10" {
		t.Fatalf("trusted client key = %q", got)
	}
	spoofed := httptest.NewRequest(http.MethodGet, "/", nil)
	spoofed.RemoteAddr = "10.1.2.3:443"
	spoofed.Header.Set("X-Forwarded-For", "198.51.100.99, 192.0.2.10, 10.1.2.3")
	if got := server.clientKey(spoofed); got != "192.0.2.10" {
		t.Fatalf("trusted client key with prepended value = %q", got)
	}
	untrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	untrusted.RemoteAddr = "198.51.100.7:443"
	untrusted.Header.Set("X-Forwarded-For", "192.0.2.10")
	if got := server.clientKey(untrusted); got != "198.51.100.7" {
		t.Fatalf("untrusted client key = %q", got)
	}
}

func TestSignedSnapshotPublishDoesNotRequireAdmin(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1}, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	service := controlsnapshots.NewService(controlsnapshots.NewMemoryStore(), rootPublic, "home")
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), headerAuthorizer{}, WithSnapshotService(service)).Handler()
	body, _ := json.Marshal(envelope)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/coordination/snapshots", bytes.NewReader(body)))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("publish snapshot status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCompanionSnapshotReadRequiresSingleUseSignedChallenge(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1}, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	snapshotService := controlsnapshots.NewService(controlsnapshots.NewMemoryStore(), rootPublic, "home")
	if err := snapshotService.Publish(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), headerAuthorizer{}, WithSnapshotService(snapshotService), WithCompanionRootKey(rootPublic)).Handler()
	challengeRecorder := httptest.NewRecorder()
	handler.ServeHTTP(challengeRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/coordination/snapshot/companion-challenge", nil))
	if challengeRecorder.Code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s", challengeRecorder.Code, challengeRecorder.Body.String())
	}
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(challengeRecorder.Body.Bytes(), &challenge); err != nil || challenge.Nonce == "" {
		t.Fatalf("challenge=%s error=%v", challengeRecorder.Body.String(), err)
	}
	signature, err := protocol.SignCompanionRequest(http.MethodGet, companionSnapshotPath, challenge.Nonce, "root-1", rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, companionSnapshotPath, nil)
	request.Header.Set("X-Go-Tunnels-Companion-Nonce", challenge.Nonce)
	request.Header.Set("X-Go-Tunnels-Companion-Key-ID", "root-1")
	request.Header.Set("X-Go-Tunnels-Companion-Signature", base64.RawURLEncoding.EncodeToString(signature))
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request)
	if first.Code != http.StatusOK || !bytes.Contains(first.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(envelope.Hash))) {
		t.Fatalf("companion snapshot status=%d body=%s", first.Code, first.Body.String())
	}
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, request)
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("replayed companion request status=%d body=%s", replay.Code, replay.Body.String())
	}
}

type allowAuthorizer struct{}

// Test handlers opt into mutation authorization explicitly. Production uses
// BrowserAuth's Origin/CSRF checks instead of this test-only admin predicate.
func newTestServer(service DeviceService, auth Authorizer, options ...ServerOption) *Server {
	options = append([]ServerOption{WithMutationAuthorizer(auth.IsAdmin)}, options...)
	return NewServer(service, auth, options...)
}

func (allowAuthorizer) IsAdmin(context.Context, *http.Request) (bool, error) { return true, nil }

type headerAuthorizer struct{}

func (headerAuthorizer) IsAdmin(_ context.Context, request *http.Request) (bool, error) {
	return request.Header.Get("X-Test-Admin") == "true", nil
}

type auditReaderStub struct {
	events []audit.Event
	limit  int
}

func (reader *auditReaderStub) List(_ context.Context, limit int) ([]audit.Event, error) {
	reader.limit = limit
	return reader.events, nil
}

func validEnrollmentRequest(t *testing.T, token, name string) devices.EnrollRequest {
	t.Helper()
	_, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wireGuardPrivate, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return devices.EnrollRequest{
		Token:              token,
		Name:               name,
		IdentityPublicKey:  base64.RawURLEncoding.EncodeToString(identityPrivate.Public().(ed25519.PublicKey)),
		WireGuardPublicKey: wireGuardPrivate.PublicKey().String(),
	}
}
