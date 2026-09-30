package workflows_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/app/control/workflows"
	"github.com/sokhrym/go-tunnels/internal/control/invites"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type latest struct{ envelope snapshot.Envelope }

func (l *latest) Latest(context.Context) (snapshot.Envelope, error) { return l.envelope, nil }

type challenges struct{ values map[string][]byte }

func (c *challenges) PutChallenge(_ context.Context, p, k string, v []byte, _ time.Duration) error {
	c.values[p+k] = bytes.Clone(v)
	return nil
}

func (c *challenges) ConsumeChallenge(_ context.Context, p, k string) ([]byte, error) {
	v := c.values[p+k]
	delete(c.values, p+k)
	return v, nil
}

func TestClaimProofBindsInviteDeviceNetworkAndOneTimeChallenge(t *testing.T) {
	ctx := context.Background()
	root, private, _ := ed25519.GenerateKey(rand.Reader)
	device, devicePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	r := invites.Record{InviteID: "invite", ProfileID: "family", DeviceID: "linux", DevicePublic: device, WireGuardPublicKey: bytes.Repeat([]byte{7}, 32), Status: invites.StatusApproved}
	store := invites.NewMemoryStore()
	if err := store.Save(ctx, r); err != nil {
		t.Fatal(err)
	}
	snap := &latest{}
	snap.envelope, _ = snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1, Devices: []snapshot.Device{{ID: "linux", Role: "client", IdentityPublicKey: base64.RawURLEncoding.EncodeToString(device), WireGuardPublicKey: base64.StdEncoding.EncodeToString(r.WireGuardPublicKey)}}, Profiles: []snapshot.AccessProfile{{ID: "family", Name: "Family", DeviceIDs: []string{"linux"}}}}, private, "root-1")
	security := &challenges{values: map[string][]byte{}}
	// Proof validation happens before a credential transaction is opened.
	s := workflows.NewActivation(nil, store, snap, security, root, "home", func() time.Time { return now }, rand.Reader)
	for _, kind := range []string{"wrong-key", "wrong-invite", "wrong-network", "noncanonical", "expired"} {
		t.Run(kind, func(t *testing.T) {
			challenge, err := s.Challenge(ctx, "invite")
			if err != nil {
				t.Fatal(err)
			}
			key := devicePrivate
			switch kind {
			case "wrong-key":
				_, key, _ = ed25519.GenerateKey(rand.Reader)
			case "wrong-invite":
				challenge.InviteID = "other"
			case "wrong-network":
				challenge.NetworkID = "other"
			case "noncanonical":
				challenge.Nonce += "="
			case "expired":
				now = now.Add(3 * time.Minute)
			}
			proof, err := workflows.SignClaim(challenge, key)
			if err == nil {
				_, err = s.Claim(ctx, "invite", proof)
			}
			if err == nil {
				t.Fatal("invalid claim accepted")
			}
		})
	}
	challenge, err := s.Challenge(ctx, "invite")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := workflows.SignClaim(challenge, devicePrivate)
	if err != nil {
		t.Fatal(err)
	}
	// Nil UoW causes the first valid request to fail after consuming the nonce.
	if _, err := s.Claim(ctx, "invite", proof); err == nil {
		t.Fatal("missing UoW accepted")
	}
	if _, err := s.Claim(ctx, "invite", proof); err != workflows.ErrInvalidClaim {
		t.Fatalf("replay error=%v", err)
	}
}

func TestChallengeRequiresExactRootSignedSnapshot(t *testing.T) {
	ctx := context.Background()
	root, private, _ := ed25519.GenerateKey(rand.Reader)
	otherRoot, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherRoot
	device, _, _ := ed25519.GenerateKey(rand.Reader)
	r := invites.Record{InviteID: "i", ProfileID: "p", DeviceID: "d", DevicePublic: device, WireGuardPublicKey: bytes.Repeat([]byte{4}, 32), Status: invites.StatusApproved}
	store := invites.NewMemoryStore()
	_ = store.Save(ctx, r)
	for _, kind := range []string{"unsigned", "wrong-root", "wrong-network", "wrong-wg", "wrong-identity", "wrong-profile", "missing-device", "pending"} {
		t.Run(kind, func(t *testing.T) {
			value := snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1, Devices: []snapshot.Device{{ID: "d", Role: "client", IdentityPublicKey: base64.RawURLEncoding.EncodeToString(device), WireGuardPublicKey: base64.StdEncoding.EncodeToString(r.WireGuardPublicKey)}}, Profiles: []snapshot.AccessProfile{{ID: "p", Name: "Profile", DeviceIDs: []string{"d"}}}}
			key := private
			switch kind {
			case "wrong-root":
				key = otherPrivate
			case "wrong-network":
				value.NetworkID = "elsewhere"
			case "wrong-wg":
				value.Devices[0].WireGuardPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
			case "wrong-identity":
				value.Devices[0].IdentityPublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
			case "wrong-profile":
				value.Profiles[0].ID = "other"
			case "missing-device":
				value.Devices = nil
				value.Profiles[0].DeviceIDs = nil
			case "pending":
				r.Status = invites.StatusPending
				pending := invites.NewMemoryStore()
				_ = pending.Save(ctx, r)
				store = pending
			}
			envelope, err := snapshot.Sign(value, key, "root-1")
			if err != nil {
				t.Fatal(err)
			}
			if kind == "unsigned" {
				envelope.Signature = nil
			}
			s := workflows.NewActivation(nil, store, &latest{envelope}, &challenges{values: map[string][]byte{}}, root, "home", nil, nil)
			if _, err := s.Challenge(ctx, "i"); err == nil {
				t.Fatal("unapproved snapshot accepted")
			}
		})
	}
}
