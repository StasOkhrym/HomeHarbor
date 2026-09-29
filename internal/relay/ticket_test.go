package relay

import (
	"errors"
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
	now = now.Add(2 * time.Minute)
	if _, err := issuer.Verify(token); !errors.Is(err, ErrExpiredTicket) {
		t.Fatalf("Verify() error=%v", err)
	}
}

func TestPacketRoundTrip(t *testing.T) {
	encoded, err := EncodePacket(Packet{SessionID: "session-1", SourceDeviceID: "a", DestinationDeviceID: "b", Payload: []byte{1, 2, 3}})
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
