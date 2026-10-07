package invites_test

import (
	"context"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/invites"
	"github.com/StasOkhrym/homeharbor/internal/invite"
	memoryinvites "github.com/StasOkhrym/homeharbor/internal/testutil/control/invites"
)

func TestReturnedBytesAreIsolated(t *testing.T) {
	store := memoryinvites.NewRepository()
	record := invites.Record{
		InviteID: "invite", Status: invites.StatusPending,
		DevicePublic: []byte{1},
		Permit:       invite.SignedPermit{Payload: []byte{2}},
		Proof:        invite.Proof{Signature: []byte{3}},
	}

	if err := store.Save(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	record.DevicePublic[0] = 9
	record.Permit.Payload[0] = 9
	record.Proof.Signature[0] = 9

	got, err := store.Get(context.Background(), "invite")
	if err != nil {
		t.Fatal(err)
	}

	if got.DevicePublic[0] != 1 || got.Permit.Payload[0] != 2 || got.Proof.Signature[0] != 3 {
		t.Fatalf("stored input alias = %#v", got)
	}

	got.DevicePublic[0] = 8
	got.Permit.Payload[0] = 8
	got.Proof.Signature[0] = 8

	again, err := store.Get(context.Background(), "invite")
	if err != nil {
		t.Fatal(err)
	}

	if again.DevicePublic[0] != 1 || again.Permit.Payload[0] != 2 || again.Proof.Signature[0] != 3 {
		t.Fatalf("returned output alias = %#v", again)
	}
}
