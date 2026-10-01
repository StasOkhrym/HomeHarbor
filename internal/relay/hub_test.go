package relay

import (
	"context"
	"testing"
)

func TestHubForwardsOnlyWithinSession(t *testing.T) {
	hub := NewHub()
	a := &recordSender{}
	b := &recordSender{}
	if err := hub.Register("s1", "a", a); err != nil {
		t.Fatal(err)
	}
	defer hub.Unregister("s1", "a")
	if err := hub.Register("s1", "b", b); err != nil {
		t.Fatal(err)
	}
	defer hub.Unregister("s1", "b")
	packet := Packet{SessionID: "s1", SourceDeviceID: "a", DestinationDeviceID: "b", Payload: []byte("ciphertext")}
	if err := hub.Forward(context.Background(), "s1", "a", packet); err != nil {
		t.Fatal(err)
	}
	if len(b.packets) != 1 || string(b.packets[0].Payload) != "ciphertext" {
		t.Fatalf("packets=%#v", b.packets)
	}
	if err := hub.Forward(context.Background(), "s2", "a", packet); err == nil {
		t.Fatal("cross-session forward succeeded")
	}
}

func TestPacketRejectsOversizedPayload(t *testing.T) {
	if _, err := EncodePacket(
		Packet{
			SessionID:           "s",
			SourceDeviceID:      "a",
			DestinationDeviceID: "b",
			Payload:             make([]byte, maxPacketPayload+1),
		},
	); err == nil {
		t.Fatal("oversized payload encoded")
	}
}

type recordSender struct{ packets []Packet }

func (r *recordSender) Send(_ context.Context, p Packet) error {
	r.packets = append(r.packets, p)
	return nil
}
