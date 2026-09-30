package coordination

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/control/snapshots"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type historyAuthenticator struct{}

func (historyAuthenticator) Authenticate(_ context.Context, credential string) (devices.Device, error) {
	if credential != "credential" {
		return devices.Device{}, errors.New("invalid credential")
	}
	return devices.Device{ID: "device-1", Status: devices.StatusActive}, nil
}

func TestHistoryRequiresExplicitDependency(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := snapshots.NewService(snapshots.NewMemoryStore(), public, "home")
	// A Latest-only constructor must not discover extra capabilities merely
	// because its concrete provider happens to implement History too.
	handler := NewHandler(historyAuthenticator{}, nil, service, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/coordination/snapshots", nil)
	request.Header.Set("Authorization", "Bearer credential")
	response := httptest.NewRecorder()
	handler.ServeHistory(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("implicit history status=%d", response.Code)
	}
}

func TestHistoryRequiresDeviceAuthAndValidCursorHash(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := snapshots.NewService(snapshots.NewMemoryStore(), public, "home")
	first, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1}, private, "root")
	if err != nil {
		t.Fatal(err)
	}
	second, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 2, PreviousHash: first.Hash}, private, "root")
	if err != nil {
		t.Fatal(err)
	}
	for _, envelope := range []snapshot.Envelope{first, second} {
		if err := service.Publish(context.Background(), envelope); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewHandlerWithHistory(historyAuthenticator{}, nil, service, nil, nil)
	for _, test := range []struct {
		name, path, credential string
		status                 int
	}{
		{"missing auth", "?after_revision=0&limit=1", "", 401},
		{"wrong auth", "?after_revision=0&limit=1", "wrong", 401},
		{"genesis page", "?after_revision=0&limit=1", "credential", 200},
		{"next page", "?after_revision=1&limit=1&after_hash=" + base64.RawURLEncoding.EncodeToString(first.Hash), "credential", 200},
		{"missing hash", "?after_revision=1&limit=1", "credential", 400},
		{"wrong hash", "?after_revision=1&limit=1&after_hash=" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "credential", 409},
		{"oversized page", "?after_revision=0&limit=17", "credential", 400},
		{"bad cursor", "?after_revision=-1&limit=1", "credential", 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/coordination/snapshots"+test.path, nil)
			if test.credential != "" {
				r.Header.Set("Authorization", "Bearer "+test.credential)
			}
			w := httptest.NewRecorder()
			handler.ServeHistory(w, r)
			if w.Code != test.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if w.Code == 200 {
				var page []snapshot.Envelope
				if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page) != 1 {
					t.Fatalf("page len=%d err=%v", len(page), err)
				}
				value, _ := snapshot.Decode(page[0])
				want := uint64(1)
				if strings.Contains(test.path, "after_revision=1") {
					want = 2
				}
				if value.Revision != want {
					t.Fatalf("revision=%d want=%d", value.Revision, want)
				}
			}
		})
	}
}

func TestSnapshotSignalIsBoundedToOneWebSocketEnvelope(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1}, private, "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotMessage(envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = make([]byte, 64<<10)
	if _, err := snapshotMessage(envelope); err == nil {
		t.Fatal("oversized signed-head frame accepted")
	}
}
