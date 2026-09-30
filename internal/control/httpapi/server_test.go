package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
	controlsnapshots "github.com/sokhrym/go-tunnels/internal/control/snapshots"
	"github.com/sokhrym/go-tunnels/internal/invite"
	"github.com/sokhrym/go-tunnels/internal/relay"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

func TestEnrollmentAPIRequiresAdminAndEnrollsDevice(t *testing.T) {
	deviceService := devices.NewService(devices.NewMemoryStore(), time.Now, nil)
	handler := NewServer(deviceService, headerAuthorizer{}).Handler()

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

	body, _ := json.Marshal(devices.EnrollRequest{Token: token.Token, Name: "laptop", IdentityPublicKey: "identity", WireGuardPublicKey: "wireguard"})
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
	deviceA, err := deviceService.Enroll(context.Background(), devices.EnrollRequest{Token: tokenA.Token, Name: "a", IdentityPublicKey: "a-identity", WireGuardPublicKey: "a-wireguard"})
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := deviceService.IssueEnrollmentToken(context.Background(), devices.RoleGateway, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deviceB, err := deviceService.Enroll(context.Background(), devices.EnrollRequest{Token: tokenB.Token, Name: "b", IdentityPublicKey: "b-identity", WireGuardPublicKey: "b-wireguard"})
	if err != nil {
		t.Fatal(err)
	}
	issuer := relay.TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	handler := NewServer(deviceService, allowAuthorizer{}, WithRelaySessionIssuer(issuer, "wss://relay.example.com/relay/v1", time.Minute)).Handler()

	request := httptest.NewRequest(http.MethodPost, "/api/v1/relay-sessions", bytes.NewBufferString(`{"session_id":"session-1","destination_device_id":"`+deviceB.ID+`"}`))
	request.Header.Set("Authorization", "Bearer "+deviceA.Credential)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		RelayURL string `json:"relay_url"`
		Ticket   string `json:"ticket"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.RelayURL == "" || response.Ticket == "" {
		t.Fatalf("incomplete relay response=%#v", response)
	}
	if claims, err := issuer.Verify(response.Ticket); err != nil || claims.DeviceID != deviceA.ID {
		t.Fatalf("ticket claims=%#v error=%v", claims, err)
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/relay-sessions", strings.NewReader(`{"session_id":"s","destination_device_id":"`+deviceB.ID+`"}`)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
}

func TestHealthEndpoints(t *testing.T) {
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}).Handler()
	for _, path := range []string{"/healthz", "/readyz"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, recorder.Code)
		}
	}
}

func TestReadinessAndSecurityHeaders(t *testing.T) {
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}, WithReadiness(func(context.Context) error {
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

func TestAdminPageUsesLocalAssets(t *testing.T) {
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "unpkg.com") || strings.Contains(body, "<style>") || !strings.Contains(body, "/assets/admin.css") {
		t.Fatalf("admin page assets are not local: %s", body)
	}
}

func TestServiceCatalogAPIUsesAdminBoundary(t *testing.T) {
	catalog := controlservices.NewService(controlservices.NewMemoryStore(), time.Now)
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), headerAuthorizer{}, WithServiceCatalog(catalog)).Handler()
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
	proof, err := item.Proof("device-1", devicePrivate, item.Code)
	if err != nil {
		t.Fatal(err)
	}
	service := controlinvites.NewService(controlinvites.NewMemoryStore(), rootPublic, "home", func() time.Time { return now })
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), headerAuthorizer{}, WithInviteService(service)).Handler()
	body, _ := json.Marshal(map[string]any{"permit": permit, "proof": proof})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/invites/proof", bytes.NewReader(body)))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("submit invite proof status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestClientKeyUsesForwardedAddressOnlyFromTrustedProxy(t *testing.T) {
	server := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}, WithTrustedProxyCIDRs([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}))
	trusted := httptest.NewRequest(http.MethodGet, "/", nil)
	trusted.RemoteAddr = "10.1.2.3:443"
	trusted.Header.Set("X-Forwarded-For", "192.0.2.10, 10.1.2.3")
	if got := server.clientKey(trusted); got != "192.0.2.10" {
		t.Fatalf("trusted client key = %q", got)
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
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), headerAuthorizer{}, WithSnapshotService(service)).Handler()
	body, _ := json.Marshal(envelope)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/coordination/snapshots", bytes.NewReader(body)))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("publish snapshot status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

type allowAuthorizer struct{}

func (allowAuthorizer) IsAdmin(context.Context, *http.Request) bool { return true }

type headerAuthorizer struct{}

func (headerAuthorizer) IsAdmin(_ context.Context, request *http.Request) bool {
	return request.Header.Get("X-Test-Admin") == "true"
}
