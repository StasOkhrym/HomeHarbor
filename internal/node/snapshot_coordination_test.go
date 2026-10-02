package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	controlprotocol "github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// Legacy WS fixtures also serve the authenticated history contract. Reconnect
// tests must not accidentally answer a history GET with a 426 upgrade error.
func serveCoordinationTestHistory(
	w http.ResponseWriter,
	r *http.Request,
	history []snapshot.Envelope,
) bool {
	if r.URL.Path != "/api/v1/coordination/snapshots" {
		return false
	}
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer credential" {
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}

	after, err := strconv.ParseUint(r.URL.Query().Get("after_revision"), 10, 64)
	if err != nil {
		w.WriteHeader(400)
		return true
	}

	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit < 1 || limit > 16 {
		w.WriteHeader(400)
		return true
	}

	if after > 0 {
		hash, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("after_hash"))
		if err != nil || len(hash) != 32 {
			w.WriteHeader(400)
			return true
		}

		found := false
		for _, envelope := range history {
			value, _ := snapshot.Decode(envelope)
			if value.Revision == after && bytes.Equal(envelope.Hash, hash) {
				found = true
				break
			}
		}

		if !found {
			w.WriteHeader(409)
			return true
		}
	}

	page := []snapshot.Envelope{}
	for _, envelope := range history {
		value, _ := snapshot.Decode(envelope)
		if value.Revision > after {
			page = append(page, envelope)
			if len(page) == limit {
				break
			}
		}
	}

	_ = json.NewEncoder(w).Encode(page)

	return true
}

func consumeCoordinationTestPeer(ctx context.Context, connection *websocket.Conn) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	for {
		var message controlprotocol.Message

		if err := wsjson.Read(ctx, connection, &message); err != nil {
			return
		}
	}
}

func TestSnapshotLiveAndReconnectHeadsFetchMissingHistory(t *testing.T) {
	for _, reconnect := range []bool{false, true} {
		t.Run(strconv.FormatBool(reconnect), func(t *testing.T) {
			public, history := signedHistory(t, 4)
			requests := make(chan uint64, 10)
			var connections atomic.Int32
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api/v1/coordination/snapshots" {
						if r.Header.Get("Authorization") != "Bearer credential" {
							w.WriteHeader(401)
							return
						}
						after, err := strconv.ParseUint(r.URL.Query().Get("after_revision"), 10, 64)
						if err != nil {
							t.Error(err)
							w.WriteHeader(400)
							return
						}
						requests <- after
						page := []snapshot.Envelope{}
						for _, envelope := range history {
							value, _ := snapshot.Decode(envelope)
							if value.Revision > after {
								page = append(page, envelope)
							}
						}
						_ = json.NewEncoder(w).Encode(page)
						return
					}
					connection, err := websocket.Accept(w, r, nil)
					if err != nil {
						t.Error(err)
						return
					}
					defer func() { _ = connection.CloseNow() }()
					var hello controlprotocol.Hello
					if err := wsjson.Read(r.Context(), connection, &hello); err != nil {
						return
					}
					if err := wsjson.Write(
						r.Context(),
						connection,
						map[string]any{
							"type": "welcome",
							"protocol": controlprotocol.Negotiated{
								Version:      controlprotocol.CurrentVersion,
								Capabilities: []string{controlprotocol.CapabilityRelay},
							},
						},
					); err != nil {
						return
					}
					count := connections.Add(1)
					heads := []snapshot.Envelope{history[1], history[3]}
					if reconnect {
						if count == 1 {
							heads = heads[:1]
						} else {
							heads = heads[1:]
						}
					}
					for _, head := range heads {
						payload, _ := json.Marshal(head)
						if err := wsjson.Write(
							r.Context(),
							connection,
							controlprotocol.Message{Type: "network.snapshot", Payload: payload},
						); err != nil {
							return
						}
					}
					if reconnect && count == 1 {
						_ = connection.Close(websocket.StatusServiceRestart, "reconnect test")
						return
					}
					for {
						var message controlprotocol.Message
						if err := wsjson.Read(r.Context(), connection, &message); err != nil {
							return
						}
					}
				}),
			)
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			applier := &cursorRecorder{cancel: cancel}
			err := RunCoordinationLoop(
				ctx,
				CoordinationConfig{
					URL:              "ws" + server.URL[len("http"):] + "/ws",
					Credential:       "credential",
					DeviceID:         "device-1",
					NetworkID:        "home",
					RootPublicKey:    public,
					ReconnectInitial: time.Millisecond,
					ReconnectMax:     2 * time.Millisecond,
				},
				applier,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := applier.revisions(); !reflect.DeepEqual(got, []uint64{2, 4}) {
				t.Fatalf("applied=%v", got)
			}
			got := []uint64{}
			for len(requests) > 0 {
				got = append(got, <-requests)
			}
			if !reflect.DeepEqual(got, []uint64{0, 2}) {
				t.Fatalf("history cursors=%v", got)
			}
		})
	}
}

func TestSnapshotHistoryRejectsOversizedBodiesRedirectsAndUntrustedTLS(t *testing.T) {
	public, history := signedHistory(t, 1)
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"body", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat(" ", maxSnapshotHistoryBytes+1)))
		}},
		{"count", func(w http.ResponseWriter, r *http.Request) {
			page := make([]snapshot.Envelope, snapshotHistoryPageSize+1)
			for i := range page {
				page[i] = history[0]
			}

			_ = json.NewEncoder(w).Encode(page)
		}},
		{"redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()

			a, cursor := &stateApplier{}, &coordinationCursor{}
			cfg := CoordinationConfig{
				URL:           "ws" + server.URL[len("http"):],
				Credential:    "credential",
				NetworkID:     "home",
				RootPublicKey: public,
			}

			if err := reconcileSnapshotHead(
				context.Background(),
				cfg,
				a,
				cursor,
				history[0],
			); err == nil {
				t.Fatal("unbounded/redirected history accepted")
			}

			if len(a.revisions) != 0 || cursor.revision != 0 {
				t.Fatal("rejected response applied")
			}
		})
	}

	t.Run("TLS", func(t *testing.T) {
		server := httptest.NewTLSServer(
			http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(history) },
			),
		)
		defer server.Close()

		cfg := CoordinationConfig{
			URL:           "wss" + server.URL[len("https"):],
			Credential:    "credential",
			NetworkID:     "home",
			RootPublicKey: public,
		}

		if _, err := fetchSnapshotHistory(context.Background(), cfg, 0, nil); err == nil {
			t.Fatal("untrusted TLS server accepted")
		}
	})
}
