package coordination

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	controlprotocol "github.com/sokhrym/go-tunnels/internal/protocol"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

func TestCoordinationRuntimeJoinsHijackedWebSockets(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1}, key, "root")
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(coordinationAuthStub{}, nil, coordinationSnapshotStub{envelope: envelope}, nil, nil)
	s := httptest.NewServer(h)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(s.URL, "http"), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer credential"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	if err := wsjson.Write(ctx, c, controlprotocol.Hello{DeviceID: "device-1", Versions: []uint16{controlprotocol.CurrentVersion}, Capabilities: []string{controlprotocol.CapabilityUDPPairV2}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		var message map[string]any
		if err := wsjson.Read(ctx, c, &message); err != nil {
			t.Fatal(err)
		}
	}
	// net/http Shutdown does not own hijacked sockets. The coordination
	// component must close and join them before App releases DB/Redis stores.
	owner, ok := any(h).(interface{ Run(context.Context) error })
	if !ok {
		t.Fatal("coordination WebSockets have no runtime shutdown owner")
	}
	runtimeCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- owner.Run(runtimeCtx) }()
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("shutdown did not join active coordination handler")
	}
	h.hub.mu.Lock()
	peers := len(h.hub.peers)
	h.hub.mu.Unlock()
	if peers != 0 {
		t.Fatal("Run returned while a session remained registered")
	}
	var message map[string]any
	if err := wsjson.Read(ctx, c, &message); err == nil {
		t.Fatal("runtime left upgraded socket open")
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("new session admitted after shutdown: %d", w.Code)
	}
}

type shutdownAuth struct{ entered, cancelled, release chan struct{} }

func (a shutdownAuth) Authenticate(ctx context.Context, _ string) (devices.Device, error) {
	close(a.entered)
	<-ctx.Done()
	close(a.cancelled)
	<-a.release
	return devices.Device{}, errors.New("cancelled")
}

func TestCoordinationShutdownJoinsAuthenticationBeforeStoresClose(t *testing.T) {
	auth := shutdownAuth{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	h := NewHandler(auth, nil, nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	requestDone := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		close(requestDone)
	}()
	select {
	case <-auth.entered:
	case <-ctx.Done():
		t.Fatal("authentication did not start")
	}

	runtimeCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Run(runtimeCtx) }()
	stop()
	select {
	case <-auth.cancelled:
	case <-ctx.Done():
		t.Fatal("shutdown did not cancel authentication")
	}

	select {
	case <-done:
		t.Error("Run returned before store operation exited")
	default:
	}

	close(auth.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("authentication handler was not joined")
	}

	<-requestDone
}
