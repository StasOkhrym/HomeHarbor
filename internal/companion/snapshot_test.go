package companion

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

func TestSnapshotSignerAddsOnlyOneClientToExistingProfile(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(time.Now)
	if err := session.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}
	previous, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices: []snapshot.Device{
			{
				ID:                 "gateway",
				Role:               "gateway",
				IdentityPublicKey:  "gateway-id",
				WireGuardPublicKey: "gateway-wg",
				OverlayAddress:     "10.200.0.1/32",
			},
		},
		Profiles: []snapshot.AccessProfile{{ID: "family", Name: "Family", ServiceIDs: []string{"cloud"}}},
		Services: []snapshot.Service{{ID: "cloud", Name: "Cloud", Kind: "web", URL: "https://cloud.example"}},
	}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSnapshotSigner(session, "home", "root-1")
	next, err := signer.SignDeviceAddition(previous, DeviceAddition{ProfileID: "family", Device: snapshot.Device{
		ID:                 "phone",
		Role:               "client",
		IdentityPublicKey:  "phone-id",
		WireGuardPublicKey: "phone-wg",
		OverlayAddress:     "10.200.0.2/32",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.VerifyNext(next, publicKey, "home", 1, previous.Hash); err != nil {
		t.Fatal(err)
	}
	value, err := snapshot.Decode(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Devices) != 2 || len(value.Profiles) != 1 || len(value.Profiles[0].DeviceIDs) != 1 ||
		value.Profiles[0].DeviceIDs[0] != "phone" {
		t.Fatalf("unexpected signed diff: %#v", value)
	}
	if len(value.Services) != 1 || value.Services[0].ID != "cloud" {
		t.Fatalf("unrelated snapshot state changed: %#v", value.Services)
	}
}

func TestSnapshotSignerCopiesOnlyExplicitProfileACLTemplates(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(time.Now)
	if err := session.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}
	previous, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices: []snapshot.Device{
			{
				ID:                 "laptop",
				Role:               "client",
				IdentityPublicKey:  "laptop-id",
				WireGuardPublicKey: "laptop-wg",
				OverlayAddress:     "10.200.0.2/32",
			},
		},
		Profiles: []snapshot.AccessProfile{
			{ID: "family", Name: "Family", DeviceIDs: []string{"laptop"}, ACLRuleIDs: []string{"lan-web"}},
		},
		ACL: []snapshot.ACLRule{
			{
				ID:             "lan-web",
				SourceDeviceID: "laptop",
				Destination:    "10.0.0.0/24",
				Protocol:       "tcp",
				PortFrom:       443,
				PortTo:         443,
			},
		},
	}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewSnapshotSigner(
		session,
		"home",
		"root-1",
	).SignDeviceAddition(previous, DeviceAddition{ProfileID: "family", Device: snapshot.Device{
		ID:                 "phone",
		Role:               "client",
		IdentityPublicKey:  "phone-id",
		WireGuardPublicKey: "phone-wg",
		OverlayAddress:     "10.200.0.3/32",
	}})
	if err != nil {
		t.Fatal(err)
	}
	value, err := snapshot.Decode(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.ACL) != 2 {
		t.Fatalf("ACL rules=%#v", value.ACL)
	}
	var copied snapshot.ACLRule
	for _, rule := range value.ACL {
		if rule.SourceDeviceID == "phone" {
			copied = rule
		}
	}
	if copied.ID != "family/phone/lan-web" || copied.Destination != "10.0.0.0/24" || copied.PortFrom != 443 {
		t.Fatalf("copied ACL=%#v", copied)
	}
}

func TestSnapshotSignerRemovesClientAndItsAccessExactly(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(time.Now)
	if err := session.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}
	previous, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: "home", Revision: 1,
		Devices: []snapshot.Device{
			{
				ID:                 "gateway",
				Role:               "gateway",
				IdentityPublicKey:  "gateway-id",
				WireGuardPublicKey: "gateway-wg",
				OverlayAddress:     "10.200.0.1/32",
			},
			{
				ID:                 "phone",
				Role:               "client",
				IdentityPublicKey:  "phone-id",
				WireGuardPublicKey: "phone-wg",
				OverlayAddress:     "10.200.0.2/32",
			},
			{
				ID:                 "laptop",
				Role:               "client",
				IdentityPublicKey:  "laptop-id",
				WireGuardPublicKey: "laptop-wg",
				OverlayAddress:     "10.200.0.3/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway", Name: "Home"}},
		Routes:   []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "192.168.1.0/24"}},
		Profiles: []snapshot.AccessProfile{
			{
				ID:         "family",
				Name:       "Family",
				DeviceIDs:  []string{"phone", "laptop"},
				ACLRuleIDs: []string{"phone-web", "laptop-web"},
			},
			{ID: "admins", Name: "Admins", DeviceIDs: []string{"laptop"}, ACLRuleIDs: []string{"laptop-web"}},
		},
		ACL: []snapshot.ACLRule{
			{
				ID:             "phone-web",
				SourceDeviceID: "phone",
				Destination:    "192.168.1.10/32",
				Protocol:       "tcp",
				PortFrom:       443,
				PortTo:         443,
			},
			{
				ID:             "laptop-web",
				SourceDeviceID: "laptop",
				Destination:    "192.168.1.10/32",
				Protocol:       "tcp",
				PortFrom:       443,
				PortTo:         443,
			},
		},
	}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	next, err := NewSnapshotSigner(
		session,
		"home",
		"root-1",
	).SignDeviceRemoval(previous, DeviceRemoval{DeviceID: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.VerifyNext(next, publicKey, "home", 1, previous.Hash); err != nil {
		t.Fatal(err)
	}
	value, err := snapshot.Decode(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Devices) != 2 {
		t.Fatalf("devices after removal=%#v", value.Devices)
	}
	for _, device := range value.Devices {
		if device.ID == "phone" {
			t.Fatal("revoked device remained in snapshot")
		}
	}
	if len(value.ACL) != 1 || value.ACL[0].ID != "laptop-web" {
		t.Fatalf("ACL after removal=%#v", value.ACL)
	}
	if len(value.Profiles[0].DeviceIDs) != 1 || value.Profiles[0].DeviceIDs[0] != "laptop" ||
		len(value.Profiles[0].ACLRuleIDs) != 1 ||
		value.Profiles[0].ACLRuleIDs[0] != "laptop-web" {
		t.Fatalf("family profile after removal=%#v", value.Profiles[0])
	}
	if len(value.Profiles[1].DeviceIDs) != 1 || len(value.Profiles[1].ACLRuleIDs) != 1 {
		t.Fatalf("unrelated profile changed=%#v", value.Profiles[1])
	}
	if len(value.Routes) != 1 || value.Routes[0].GatewayID != "gateway" {
		t.Fatalf("unrelated routes changed=%#v", value.Routes)
	}
}

func TestSnapshotSignerRejectsUnsafeDeviceRemoval(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	session := NewSession(time.Now)

	if err := session.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}

	previous, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: "home", Revision: 1,
		Devices: []snapshot.Device{
			{
				ID:                 "gateway",
				Role:               "gateway",
				IdentityPublicKey:  "gateway-id",
				WireGuardPublicKey: "gateway-wg",
				OverlayAddress:     "10.200.0.1/32",
			},
			{
				ID:                 "phone",
				Role:               "client",
				IdentityPublicKey:  "phone-id",
				WireGuardPublicKey: "phone-wg",
				OverlayAddress:     "10.200.0.2/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway", Name: "Home"}},
		Routes:   []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "192.168.1.0/24"}},
	}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	signer := NewSnapshotSigner(session, "home", "root-1")
	for _, deviceID := range []string{"missing", "gateway"} {
		if _, err := signer.SignDeviceRemoval(
			previous,
			DeviceRemoval{DeviceID: deviceID},
		); !errors.Is(
			err,
			ErrInvalidSnapshotDiff,
		) {
			t.Fatalf("device %q removal error=%v", deviceID, err)
		}
	}

	tampered := previous
	tampered.Payload = append([]byte(nil), previous.Payload...)
	tampered.Payload[0] ^= 1

	if _, err := signer.SignDeviceRemoval(tampered, DeviceRemoval{DeviceID: "phone"}); err == nil {
		t.Fatal("tampered head accepted")
	}
}

func TestSnapshotSignerAllocatesOverlayFromPool(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	session := NewSession(time.Now)

	if err := session.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}

	previous, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices: []snapshot.Device{
			{
				ID:                 "gateway",
				Role:               "gateway",
				IdentityPublicKey:  "gateway-id",
				WireGuardPublicKey: "gateway-wg",
				OverlayAddress:     "10.200.0.1/32",
			},
		},
		Profiles: []snapshot.AccessProfile{{ID: "family", Name: "Family"}},
	}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	next, err := NewSnapshotSigner(
		session,
		"home",
		"root-1",
	).SignDeviceAdditionFromPool(previous, DeviceAddition{ProfileID: "family", Device: snapshot.Device{
		ID: "phone", Role: "client", IdentityPublicKey: "phone-id", WireGuardPublicKey: "phone-wg",
	}}, netip.MustParsePrefix("10.200.0.0/29"))
	if err != nil {
		t.Fatal(err)
	}

	value, err := snapshot.Decode(next)
	if err != nil {
		t.Fatal(err)
	}

	if value.Devices[1].OverlayAddress != "10.200.0.2/32" {
		t.Fatalf("allocated overlay=%s", value.Devices[1].OverlayAddress)
	}
}

func TestSnapshotSignerRejectsAnythingOutsideExactDeviceAddition(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	session := NewSession(time.Now)

	if err := session.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}

	previous, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: "home", Revision: 1,
		Profiles: []snapshot.AccessProfile{{ID: "family", Name: "Family"}},
	}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	signer := NewSnapshotSigner(session, "home", "root-1")
	cases := []DeviceAddition{
		{ProfileID: "missing", Device: snapshot.Device{ID: "phone", Role: "client"}},
		{ProfileID: "family", Device: snapshot.Device{ID: "gateway-2", Role: "gateway"}},
		{ProfileID: "family", Device: snapshot.Device{ID: "phone", Role: "client"}},
	}
	for index, addition := range cases {
		if _, err := signer.SignDeviceAddition(previous, addition); err == nil {
			t.Errorf("case %d: SignDeviceAddition() error=nil", index)
		}
	}

	if _, err := signer.SignDeviceAddition(
		previous,
		DeviceAddition{
			ProfileID: "family",
			Device: snapshot.Device{
				ID:                 "phone",
				Role:               "client",
				IdentityPublicKey:  "id",
				WireGuardPublicKey: "wg",
				OverlayAddress:     "0.0.0.0/0",
			},
		},
	); !errors.Is(
		err,
		ErrInvalidSnapshotDiff,
	) {
		t.Fatalf("invalid profile device fields error=%v", err)
	}
}

func TestSnapshotSignerRejectsTamperedHeadAndLockedSession(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	previous, err := snapshot.Sign(
		snapshot.NetworkSnapshot{
			NetworkID: "home",
			Revision:  1,
			Profiles:  []snapshot.AccessProfile{{ID: "family", Name: "Family"}},
		},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}

	session := NewSession(time.Now)

	if err := session.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}

	signer := NewSnapshotSigner(session, "home", "root-1")
	tampered := previous
	tampered.Hash = append([]byte(nil), previous.Hash...)
	tampered.Hash[0] ^= 1

	if _, err := signer.SignDeviceAddition(
		tampered,
		DeviceAddition{
			ProfileID: "family",
			Device: snapshot.Device{
				ID:                 "phone",
				Role:               "client",
				IdentityPublicKey:  "id",
				WireGuardPublicKey: "wg",
				OverlayAddress:     "10.200.0.2/32",
			},
		},
	); err == nil {
		t.Fatal("tampered snapshot accepted")
	}

	wrongKeyID := previous
	wrongKeyID.KeyID = "rotated-root"

	if _, err := signer.SignDeviceAddition(
		wrongKeyID,
		DeviceAddition{
			ProfileID: "family",
			Device: snapshot.Device{
				ID:                 "phone",
				Role:               "client",
				IdentityPublicKey:  "id",
				WireGuardPublicKey: "wg",
				OverlayAddress:     "10.200.0.2/32",
			},
		},
	); err == nil {
		t.Fatal("snapshot with unexpected key ID accepted")
	}

	now := time.Now()
	locked := NewSession(func() time.Time { return now })

	if err := locked.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}

	now = now.Add(16 * time.Minute)

	if _, err := NewSnapshotSigner(
		locked,
		"home",
		"root-1",
	).SignDeviceAddition(previous, DeviceAddition{ProfileID: "family", Device: snapshot.Device{ID: "phone", Role: "client", IdentityPublicKey: "id", WireGuardPublicKey: "wg", OverlayAddress: "10.200.0.2/32"}}); !errors.Is(
		err,
		ErrRootKeyLocked,
	) {
		t.Fatalf("locked session error=%v", err)
	}
}
