package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
	memorydevices "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
)

func TestRotationResponseIncludesExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	svc := devices.NewService(memorydevices.NewRepository(), func() time.Time { return now }, nil)

	token, err := svc.IssueEnrollmentToken(context.Background(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	d, err := svc.Enroll(context.Background(), validEnrollmentRequest(t, token.Token, "rotation"))
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestServer(svc, headerAuthorizer{}, Dependencies{}).Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/credentials/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+d.Credential)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, req)
	var lease struct {
		DeviceID   string    `json:"device_id"`
		Credential string    `json:"credential"`
		ExpiresAt  time.Time `json:"expires_at"`
	}

	if err := json.Unmarshal(response.Body.Bytes(), &lease); err != nil {
		t.Fatal(err)
	}

	if response.Code != http.StatusOK || lease.DeviceID != d.ID || lease.Credential == "" ||
		!lease.ExpiresAt.Equal(now.Add(devices.CredentialTTL)) {
		t.Fatalf(
			"rotation did not return its issuance lease: status=%d device=%q expiry=%v",
			response.Code,
			lease.DeviceID,
			lease.ExpiresAt,
		)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential response may be cached")
	}
}

type recoveryHTTPStub struct{ calls int }

func (s *recoveryHTTPStub) Challenge(
	_ context.Context,
	id string,
) (protocol.CredentialChallenge, error) {
	s.calls++
	return protocol.CredentialChallenge{
		Version:   1,
		NetworkID: "network",
		DeviceID:  id,
		Nonce:     "nonce",
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	}, nil
}

func (s *recoveryHTTPStub) Recover(
	context.Context,
	protocol.CredentialProof,
) (protocol.CredentialLease, error) {
	s.calls++
	return protocol.CredentialLease{}, protocol.ErrInvalidCredentialProof
}

func TestRecoveryHTTPIsPublicNoStoreAndFailClosed(t *testing.T) {
	recovery := &recoveryHTTPStub{}
	deps := Dependencies{Resources: ResourceDependencies{Recovery: recovery}}

	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		headerAuthorizer{},
		deps,
	).Handler()
	for _, id := range []string{"known", "unknown"} {
		response := httptest.NewRecorder()

		handler.ServeHTTP(
			response,
			httptest.NewRequest(
				http.MethodPost,
				"/api/v1/devices/credentials/challenge",
				strings.NewReader(`{"device_id":"`+id+`"}`),
			),
		)

		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("challenge status=%d", response.Code)
		}
	}

	response := httptest.NewRecorder()

	handler.ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodPost,
			"/api/v1/devices/credentials/recovery",
			strings.NewReader(`{"challenge":{},"signature":""}`),
		),
	)

	if response.Code != http.StatusUnauthorized ||
		!strings.Contains(response.Body.String(), "invalid_credential_proof") ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid recovery status=%d", response.Code)
	}

	before := recovery.calls
	deps.Security.DeviceLimiter = NewSharedRateLimiter(
		unavailableLimitStore{},
		"onboarding",
		5,
		time.Minute,
	)

	handler = newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		headerAuthorizer{},
		deps,
	).Handler()
	for _, endpoint := range []string{"challenge", "recovery"} {
		response := httptest.NewRecorder()

		handler.ServeHTTP(
			response,
			httptest.NewRequest(
				http.MethodPost,
				"/api/v1/devices/credentials/"+endpoint,
				strings.NewReader(`{}`),
			),
		)

		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("Redis outage status=%d", response.Code)
		}
	}

	if recovery.calls != before {
		t.Fatal("unavailable quota reached recovery service")
	}
}
