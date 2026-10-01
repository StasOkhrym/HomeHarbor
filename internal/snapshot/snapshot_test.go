package snapshot

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestSignVerifyAndAcceptNextSnapshot(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(
		NetworkSnapshot{
			NetworkID: "home",
			Revision:  1,
			Services:  []Service{{ID: "cloud", Name: "Nextcloud", Kind: "web", URL: "https://cloud.home.example.com"}},
		},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyNext(signed, publicKey, "home", 0, nil); err != nil {
		t.Fatal(err)
	}
	if len(signed.Payload) == 0 || len(signed.Hash) != 32 || len(signed.Signature) != ed25519.SignatureSize {
		t.Fatalf("signed envelope = %#v", signed)
	}

	next, err := Sign(
		NetworkSnapshot{
			NetworkID:    "home",
			Revision:     2,
			PreviousHash: signed.Hash,
			Services: []Service{
				{ID: "cloud", Name: "Nextcloud", Kind: "web", URL: "https://cloud.home.example.com"},
			},
		},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyNext(next, publicKey, "home", 1, signed.Hash); err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(next, publicKey, "home")
	if err != nil {
		t.Fatalf("verify current head: %v", err)
	}
	if verified.Revision != 2 {
		t.Fatalf("verified revision = %d, want 2", verified.Revision)
	}
}

func TestVerifyRejectsTamperingRollbackAndGap(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(NetworkSnapshot{NetworkID: "home", Revision: 1}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	tampered := signed
	tampered.Payload = append([]byte(nil), signed.Payload...)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if err = VerifyNext(tampered, publicKey, "home", 0, nil); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("tampered error = %v", err)
	}
	if err = VerifyNext(signed, publicKey, "home", 1, signed.Hash); !errors.Is(err, ErrRevisionRollback) {
		t.Fatalf("rollback error = %v", err)
	}
	gap, err := Sign(NetworkSnapshot{NetworkID: "home", Revision: 3, PreviousHash: signed.Hash}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyNext(gap, publicKey, "home", 1, signed.Hash); !errors.Is(err, ErrRevisionGap) {
		t.Fatalf("gap error = %v", err)
	}
}

func TestSignRejectsInvalidService(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Sign(
		NetworkSnapshot{NetworkID: "home", Revision: 1, Services: []Service{{ID: "cloud", URL: "http://cloud.home"}}},
		privateKey,
		"root-1",
	); err == nil {
		t.Fatal("insecure service URL accepted")
	}
}

func TestSignRejectsReferencesThatCouldBroadenGatewayAccess(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value := NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices:   []Device{{ID: "client", OverlayAddress: "100.64.0.2/32"}},
		Gateways:  []Gateway{{DeviceID: "unknown"}},
	}
	if _, err = Sign(value, privateKey, "root-1"); err == nil {
		t.Fatal("gateway referencing unknown device was accepted")
	}

	value = NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices:   []Device{{ID: "client", Role: "client", OverlayAddress: "100.64.0.2/32"}},
		Gateways:  []Gateway{{DeviceID: "client"}},
	}
	if _, err = Sign(value, privateKey, "root-1"); err == nil {
		t.Fatal("client device was accepted as a gateway")
	}

	value = NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices:   []Device{{ID: "client", OverlayAddress: "100.64.0.2/32"}},
		ACL: []ACLRule{
			{ID: "bad", SourceDeviceID: "client", Destination: "10.0.0.0/24", Protocol: "icmp", PortFrom: 1, PortTo: 1},
		},
	}
	if _, err = Sign(value, privateKey, "root-1"); err == nil {
		t.Fatal("unsupported ACL protocol was accepted")
	}
}

func TestSignRejectsServiceCredentialsAndFragments(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, raw := range []string{"https://user:password@cloud.home", "https://cloud.home/#fragment"} {
		if _, err = Sign(
			NetworkSnapshot{
				NetworkID: "home",
				Revision:  1,
				Services:  []Service{{ID: "cloud", Name: "Cloud", URL: raw}},
			},
			privateKey,
			"root-1",
		); err == nil {
			t.Fatalf("unsafe service URL accepted: %s", raw)
		}
	}
}

func TestSignValidatesOptionalServiceURLs(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	valid := NetworkSnapshot{NetworkID: "home", Revision: 1, Services: []Service{
		{
			ID:        "cloud",
			Name:      "Cloud",
			Kind:      "native",
			URL:       "https://cloud.home",
			NativeURL: "nextcloud://cloud.home",
			HealthURL: "https://cloud.home/health",
		},
	}}

	if _, err := Sign(valid, privateKey, "root-1"); err != nil {
		t.Fatal(err)
	}

	for index, service := range []Service{
		{ID: "cloud", Name: "Cloud", Kind: "web", URL: "https://cloud.home", NativeURL: "javascript:alert(1)"},
		{ID: "cloud", Name: "Cloud", Kind: "web", URL: "https://cloud.home", HealthURL: "http://cloud.home/health"},
	} {
		if _, err := Sign(
			NetworkSnapshot{NetworkID: "home", Revision: 1, Services: []Service{service}},
			privateKey,
			"root-1",
		); err == nil {
			t.Errorf("case %d: unsafe optional URL accepted", index)
		}
	}
}

func TestSignRejectsDefaultRouteAdvertisement(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	value := NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices:   []Device{{ID: "gateway", OverlayAddress: "100.64.0.1/32"}},
		Gateways:  []Gateway{{DeviceID: "gateway"}},
		Routes:    []Route{{ID: "internet", GatewayID: "gateway", Prefix: "0.0.0.0/0"}},
	}

	if _, err := Sign(value, privateKey, "root-1"); err == nil {
		t.Fatal("default route advertisement was accepted")
	}
}

func TestSignRejectsUnsafeRouteDNSMetadata(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	base := NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices:   []Device{{ID: "gateway", Role: "gateway", OverlayAddress: "100.64.0.1/32"}},
		Gateways:  []Gateway{{DeviceID: "gateway"}},
	}
	for _, route := range []Route{
		{ID: "outside", GatewayID: "gateway", Prefix: "10.0.0.0/24", Resolver: "192.168.1.1", DomainSuffix: "home.arpa"},
		{ID: "injection", GatewayID: "gateway", Prefix: "10.0.0.0/24", Resolver: "10.0.0.53", DomainSuffix: "home.arpa;revert"},
	} {
		value := base
		value.Routes = []Route{route}

		if _, err := Sign(value, privateKey, "root-1"); err == nil {
			t.Fatalf("unsafe route metadata accepted: %#v", route)
		}
	}
}

func TestSignCanonicalizesRouteDNSMetadata(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := Sign(NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices:   []Device{{ID: "gateway", Role: "gateway", OverlayAddress: "100.64.0.1/32"}},
		Gateways:  []Gateway{{DeviceID: "gateway"}},
		Routes: []Route{
			{
				ID:           "lan",
				GatewayID:    "gateway",
				Prefix:       "10.20.0.0/16",
				Resolver:     "10.20.0.53",
				DomainSuffix: "Home.ARPA.",
			},
		},
	}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	value, err := Decode(signed)
	if err != nil {
		t.Fatal(err)
	}

	if value.Routes[0].DomainSuffix != "home.arpa" {
		t.Fatalf("canonical suffix = %q", value.Routes[0].DomainSuffix)
	}
}

func TestSignRejectsUnboundProfileReferencesAndDefaultACL(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value := NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Profiles: []AccessProfile{
			{ID: "family", Name: "Family", DeviceIDs: []string{"missing"}, ServiceIDs: []string{"missing"}},
		},
	}
	if _, err := Sign(value, privateKey, "root-1"); err == nil {
		t.Fatal("unbound profile references were accepted")
	}
	value = NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices:   []Device{{ID: "client", OverlayAddress: "100.64.0.2/32"}},
		ACL: []ACLRule{
			{
				ID:             "all",
				SourceDeviceID: "client",
				Destination:    "0.0.0.0/0",
				Protocol:       "tcp",
				PortFrom:       443,
				PortTo:         443,
			},
		},
	}
	if _, err := Sign(value, privateKey, "root-1"); err == nil {
		t.Fatal("default ACL destination was accepted")
	}
}
