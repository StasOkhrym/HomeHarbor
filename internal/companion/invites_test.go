package companion

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/control/httpapi"
	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	controlsnapshots "github.com/sokhrym/go-tunnels/internal/control/snapshots"
	"github.com/sokhrym/go-tunnels/internal/invite"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

func TestRemoteApproverRetriesSnapshotPublicationAfterActivation(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	local, err := invite.New("home", "family", time.Hour, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := invite.SignPermit(local.Permit, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	_, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := local.Proof("phone", devicePrivate, local.Code, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	store := controlinvites.NewMemoryStore()
	inviteService := controlinvites.NewService(
		store,
		rootPublic,
		"home",
		func() time.Time { return now },
		controlinvites.WithApprovalWorkflow(approvalFixture{store: store, root: rootPublic}),
	)
	if err := inviteService.SubmitProof(context.Background(), permit, proof); err != nil {
		t.Fatal(err)
	}
	snapshotService := controlsnapshots.NewService(controlsnapshots.NewMemoryStore(), rootPublic, "home")
	initial, err := snapshot.Sign(
		snapshot.NetworkSnapshot{
			NetworkID: "home",
			Revision:  1,
			Profiles:  []snapshot.AccessProfile{{ID: "family", Name: "Family"}},
		},
		rootPrivate,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotService.Publish(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	handler := httpapi.NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAllAuthorizer{}, httpapi.WithInviteService(inviteService), httpapi.WithSnapshotService(snapshotService), httpapi.WithCompanionRootKey(rootPublic)).
		Handler()
	server := httptest.NewServer(handler)
	defer server.Close()
	approver := RemoteApprover{
		Endpoint:    server.URL,
		KeyID:       "root-1",
		OverlayPool: netip.MustParsePrefix("10.200.0.0/29"),
	}
	if err := approver.Approve(context.Background(), local.Permit.InviteID, local.Code, rootPrivate); err != nil {
		t.Fatal(err)
	}
	if err := approver.PublishSnapshot(context.Background(), local.Permit.InviteID, rootPrivate); err != nil {
		t.Fatal(err)
	}
	latest, err := snapshotService.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	value, err := snapshot.Decode(latest)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Devices) != 1 || value.Devices[0].ID != "phone" || value.Devices[0].OverlayAddress != "10.200.0.1/32" {
		t.Fatalf("published device=%#v", value.Devices)
	}
	if value.Devices[0].WireGuardPublicKey != base64.StdEncoding.EncodeToString(proof.WireGuardPublicKey) {
		t.Fatalf("published nonstandard WireGuard key %q", value.Devices[0].WireGuardPublicKey)
	}
}

func TestRemoteApproverPublishesSignedDeviceRemoval(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshotService := controlsnapshots.NewService(controlsnapshots.NewMemoryStore(), rootPublic, "home")
	initial, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: "home", Revision: 1,
		Devices: []snapshot.Device{
			{
				ID:                 "phone",
				Role:               "client",
				IdentityPublicKey:  "phone-id",
				WireGuardPublicKey: "phone-wg",
				OverlayAddress:     "10.200.0.2/32",
			},
		},
		Profiles: []snapshot.AccessProfile{{ID: "family", Name: "Family", DeviceIDs: []string{"phone"}}},
	}, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotService.Publish(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	handler := httpapi.NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAllAuthorizer{}, httpapi.WithSnapshotService(snapshotService), httpapi.WithCompanionRootKey(rootPublic)).
		Handler()
	server := httptest.NewServer(handler)
	defer server.Close()

	approver := RemoteApprover{Endpoint: server.URL, KeyID: "root-1"}
	if err := approver.PublishDeviceRemoval(context.Background(), "phone", rootPrivate); err != nil {
		t.Fatal(err)
	}
	latest, err := snapshotService.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	value, err := snapshot.Decode(latest)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Devices) != 0 || len(value.Profiles) != 1 || len(value.Profiles[0].DeviceIDs) != 0 {
		t.Fatalf("device removal was not published: %#v", value)
	}
}

func TestRemoteApproverBlocksInviteAfterFiveInvalidCodes(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	local, err := invite.New("home", "family", time.Hour, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := invite.SignPermit(local.Permit, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	_, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := local.Proof("phone", devicePrivate, local.Code, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	service := controlinvites.NewService(
		controlinvites.NewMemoryStore(),
		rootPublic,
		"home",
		func() time.Time { return now },
	)
	if err := service.SubmitProof(context.Background(), permit, proof); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(httpapi.NewServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAllAuthorizer{},
		httpapi.WithInviteService(service),
	).Handler())
	defer server.Close()
	approver := RemoteApprover{Endpoint: server.URL, KeyID: "root-1", Attempts: NewMemoryInviteAttemptStore()}
	wrongCode := "00000000"
	if wrongCode == local.Code {
		wrongCode = "00000001"
	}
	for range 5 {
		if err := approver.Approve(context.Background(), local.Permit.InviteID, wrongCode, rootPrivate); err == nil {
			t.Fatal("invalid code unexpectedly approved")
		}
	}
	if err := approver.Approve(context.Background(), local.Permit.InviteID, local.Code, rootPrivate); err == nil {
		t.Fatal("correct code succeeded after five invalid attempts")
	}
}

func TestValidateControlEndpointRejectsUnsafeDestinations(t *testing.T) {
	for _, endpoint := range []string{"https://control.example", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if err := validateControlEndpoint(endpoint); err != nil {
			t.Fatalf("endpoint %q rejected: %v", endpoint, err)
		}
	}

	for _, endpoint := range []string{"http://control.example", "https://user:password@control.example", "https://control.example/base", "https://control.example/?debug=1"} {
		if err := validateControlEndpoint(endpoint); err == nil {
			t.Fatalf("unsafe endpoint %q accepted", endpoint)
		}
	}
}

type allowAllAuthorizer struct{}

func (allowAllAuthorizer) IsAdmin(context.Context, *http.Request) (bool, error) { return true, nil }
