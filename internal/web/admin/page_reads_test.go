package admin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/invites"
	controlsnapshots "github.com/StasOkhrym/homeharbor/internal/control/snapshots"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type inviteReaderStub struct {
	calls  int
	result invites.Record
	err    error
}

func (reader *inviteReaderStub) Get(context.Context, string) (invites.Record, error) {
	reader.calls++
	return reader.result, reader.err
}

type snapshotReaderStub struct{ err error }

func (reader snapshotReaderStub) Latest(context.Context) (snapshot.Envelope, error) {
	return snapshot.Envelope{}, reader.err
}

func TestInviteReadRejectsLongIDBeforeQueryAndHidesStorageErrors(t *testing.T) {
	reader := &inviteReaderStub{}
	model := NewPage("invites", "", "")

	LoadInvite(t.Context(), strings.Repeat("x", 129), reader, &model)

	if reader.calls != 0 || model.InviteError == "" {
		t.Fatalf("long invite ID queried store: calls=%d view=%+v", reader.calls, model)
	}

	reader.err = errors.New("SQL credentials must not reach the browser")
	model = NewPage("invites", "", "")

	LoadInvite(t.Context(), " invite-1 ", reader, &model)

	if reader.calls != 1 || model.Values.Get("invite_id") != "invite-1" ||
		model.InviteError == "" || strings.Contains(model.InviteError, "SQL credentials") {
		t.Fatalf("invite failure leaked or lost input: calls=%d view=%+v", reader.calls, model)
	}
}

func TestSignedStateDistinguishesUnpublishedFromStoreFailure(t *testing.T) {
	model := NewPage("security", "", "")

	LoadSignedState(
		t.Context(),
		snapshotReaderStub{err: controlsnapshots.ErrSnapshotUnavailable},
		&model,
	)

	if model.Signed != nil || model.SignedState != "No signed configuration has been published" {
		t.Fatalf("unpublished snapshot view=%+v", model)
	}

	model = NewPage("security", "", "")

	LoadSignedState(t.Context(), snapshotReaderStub{err: errors.New("SQL secret")}, &model)

	if model.Signed != nil || model.SignedState != "Signed configuration could not be loaded" {
		t.Fatalf("failed snapshot view=%+v", model)
	}
}
