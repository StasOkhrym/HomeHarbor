package companion

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/control/httpapi"
	controlsnapshots "github.com/sokhrym/go-tunnels/internal/control/snapshots"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type bootstrapAuthorizer struct{}

func (bootstrapAuthorizer) IsAdmin(context.Context, *http.Request) (bool, error) { return false, nil }

func TestLoadAndSignInitialSnapshotManifest(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "initial-snapshot.toml")
	manifest := `network_id = "home"

[[devices]]
id = "gateway"
role = "gateway"
identity_public_key = "gateway-identity"
wireguard_public_key = "gateway-wireguard"
overlay_address = "10.200.0.1/32"

[[gateways]]
device_id = "gateway"
name = "Home"

[[routes]]
id = "lan"
gateway_id = "gateway"
prefix = "192.168.50.0/24"

[[services]]
id = "cloud"
name = "Cloud"
kind = "web"
url = "https://cloud.example"

[[profiles]]
id = "family"
name = "Family"
device_ids = ["gateway"]
service_ids = ["cloud"]

[[acl]]
id = "family-cloud"
source_device_id = "gateway"
destination = "192.168.50.0/24"
protocol = "tcp"
port_from = 443
port_to = 443
`
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSnapshotManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := loaded.SignInitialSnapshot(privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.VerifyNext(envelope, privateKey.Public().(ed25519.PublicKey), "home", 0, nil); err != nil {
		t.Fatal(err)
	}
	value, err := snapshot.Decode(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if value.Revision != 1 || len(value.Gateways) != 1 || len(value.Profiles) != 1 || len(value.ACL) != 1 {
		t.Fatalf("initial snapshot=%#v", value)
	}
}

func TestSignInitialSnapshotRequiresGateway(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, err = (SnapshotManifest{NetworkID: "home"}).SignInitialSnapshot(privateKey, "root-1")

	if err == nil {
		t.Fatal("empty initial snapshot was accepted")
	}
}

func TestPublishInitialSnapshotUsesVersionedControlEndpoint(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := (SnapshotManifest{
		NetworkID: "home",
		Devices:   []ManifestDevice{{ID: "gateway", Role: "gateway", IdentityPublicKey: "identity", WireGuardPublicKey: "wireguard", OverlayAddress: "10.200.0.1/32"}},
		Gateways:  []ManifestGateway{{DeviceID: "gateway"}},
	}).SignInitialSnapshot(privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	var received snapshot.Envelope
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/coordination/snapshots" || request.Method != http.MethodPost {
			t.Fatalf("request=%s %s", request.Method, request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	if err := (RemoteApprover{Client: server.Client(), Endpoint: server.URL}).PublishInitialSnapshot(
		t.Context(),
		envelope,
	); err != nil {
		t.Fatal(err)
	}
	if received.Version != envelope.Version || string(received.Hash) != string(envelope.Hash) {
		t.Fatalf("received envelope=%#v", received)
	}
}

func TestInitialSnapshotPublishesOnlyIntoEmptyControlStore(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := (SnapshotManifest{
		NetworkID: "home",
		Devices:   []ManifestDevice{{ID: "gateway", Role: "gateway", IdentityPublicKey: "identity", WireGuardPublicKey: "wireguard", OverlayAddress: "10.200.0.1/32"}},
		Gateways:  []ManifestGateway{{DeviceID: "gateway"}},
	}).SignInitialSnapshot(rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	service := controlsnapshots.NewService(controlsnapshots.NewMemoryStore(), rootPublic, "home")
	handler := httpapi.NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), bootstrapAuthorizer{}, httpapi.WithSnapshotService(service), httpapi.WithCompanionRootKey(rootPublic)).
		Handler()
	server := httptest.NewServer(handler)
	defer server.Close()
	approver := RemoteApprover{Client: server.Client(), Endpoint: server.URL}
	if err := approver.PublishInitialSnapshot(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := approver.PublishInitialSnapshot(t.Context(), envelope); err == nil {
		t.Fatal("initial snapshot was allowed to reset an existing store")
	}
}
