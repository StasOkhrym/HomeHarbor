package relay

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTicketRoundTripAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	issuer := TicketIssuer{Key: []byte("01234567890123456789012345678901"), Now: func() time.Time { return now }}
	token, err := issuer.Issue("session-1", "device-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := issuer.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.SessionID != "session-1" || claims.DeviceID != "device-1" {
		t.Fatalf("claims=%#v", claims)
	}
	if claims.Version != TicketVersion || claims.Audience != RelayAudience {
		t.Fatalf("claims metadata=%#v", claims)
	}
	now = now.Add(2 * time.Minute)
	if _, err := issuer.Verify(token); !errors.Is(err, ErrExpiredTicket) {
		t.Fatalf("Verify() error=%v", err)
	}
}

func TestTicketRejectsMalformedClaims(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	issuer := TicketIssuer{Key: []byte("01234567890123456789012345678901"), Now: func() time.Time { return now }}
	token, err := issuer.Issue("session-1", "device-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatal("unexpected ticket format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"aud":"relay"`), []byte(`"aud":"other"`), 1)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	forged := encoded + "." + issuer.sign(encoded)
	if _, err := issuer.Verify(forged); !errors.Is(err, ErrInvalidTicket) {
		t.Fatalf("Verify() error=%v, want ErrInvalidTicket", err)
	}
}

func TestPeerTicketBindsDestination(t *testing.T) {
	issuer := TicketIssuer{Key: []byte("01234567890123456789012345678901")}

	token, err := issuer.IssueForPeer("session-1", "device-1", "device-2", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := issuer.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	if err := claims.ValidatePeer("session-1", "device-1", "device-2"); err != nil {
		t.Fatal(err)
	}

	if err := claims.ValidatePeer("session-1", "device-1", "device-3"); err == nil {
		t.Fatal("ticket was accepted for a different destination")
	}
}

func TestPacketRoundTrip(t *testing.T) {
	encoded, err := EncodePacket(
		Packet{SessionID: "session-1", SourceDeviceID: "a", DestinationDeviceID: "b", Payload: []byte{1, 2, 3}},
	)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePacket(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SessionID != "session-1" || string(decoded.Payload) != string([]byte{1, 2, 3}) {
		t.Fatalf("packet=%#v", decoded)
	}
}

func TestRelayTicketFromRequestRequiresBearerAuthorization(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/relay/v1?ticket=query-secret", nil)
	request.Header.Set("Authorization", "Bearer header-secret")
	if got := relayTicketFromRequest(request); got != "header-secret" {
		t.Fatalf("ticket = %q", got)
	}
	request = httptest.NewRequest(http.MethodGet, "/relay/v1?ticket=query-secret", nil)
	if got := relayTicketFromRequest(request); got != "" {
		t.Fatalf("query ticket accepted: %q", got)
	}
}
