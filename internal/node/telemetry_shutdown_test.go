package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func TestShutdownReportUsesFreshAdmissionWithoutApplyingSnapshot(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "older-server", true: "telemetry"}[supported],
			func(t *testing.T) {
				received := make(chan protocol.TelemetryReport, 1)

				source, err := NewRuntimeTelemetry(
					TelemetryConfig{DeviceID: "client", Role: "client"},
				)
				if err != nil {
					t.Fatal(err)
				}

				source.Stopped()
				server := httptest.NewServer(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Header.Get("Authorization") != "Bearer credential" {
							t.Error("shutdown lost credential")
						}

						c, err := websocket.Accept(w, r, nil)
						if err != nil {
							return
						}
						defer func() { _ = c.CloseNow() }()

						var hello protocol.Hello
						if wsjson.Read(r.Context(), c, &hello) != nil {
							return
						}

						caps := []string{protocol.CapabilityUDPPair}
						if supported {
							caps = append(caps, protocol.CapabilityTelemetry)
						}

						if wsjson.Write(
							r.Context(),
							c,
							protocol.Welcome{
								Type: "welcome",
								Protocol: protocol.Negotiated{
									Version:      protocol.CurrentVersion,
									Capabilities: caps,
								},
								TelemetryGeneration: 77,
							},
						) != nil {
							return
						}
						if !supported {
							var msg protocol.Message

							if wsjson.Read(r.Context(), c, &msg) == nil {
								t.Error("old server received unnegotiated telemetry")
							}

							return
						}
						// The final report channel must never apply even a newly supplied head.
						if wsjson.Write(
							r.Context(),
							c,
							protocol.Message{
								Type: "network.snapshot",
								Payload: json.RawMessage(
									`{"untrusted":"never apply during shutdown"}`,
								),
							},
						) != nil {
							return
						}

						var message protocol.Message
						if wsjson.Read(r.Context(), c, &message) != nil {
							return
						}

						var report protocol.TelemetryReport
						if message.Type != "telemetry.report" ||
							json.Unmarshal(message.Payload, &report) != nil {
							t.Error("missing stopped report")

							return
						}

						received <- report
						if wsjson.Read(r.Context(), c, &message) != nil {
							return
						}

						if message.Type != "heartbeat" {
							t.Error("missing ordered drain")
						}

						_ = wsjson.Write(r.Context(), c, protocol.Message{Type: "heartbeat.ack"})
					}),
				)
				defer server.Close()

				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()

				cfg := CoordinationConfig{
					URL:        "ws" + strings.TrimPrefix(server.URL, "http"),
					Credential: "credential",
					DeviceID:   "client",
					Telemetry:  source,
				}

				if err := ReportRuntimeShutdown(ctx, cfg); err != nil {
					t.Fatal(err)
				}

				if supported {
					select {
					case report := <-received:
						if report.Generation != 77 || report.Sequence != 1 ||
							report.State != protocol.RuntimeStopped {
							t.Fatalf("invalid final report: %+v", report)
						}
					default:
						t.Fatal("shutdown report missing")
					}
				}
			},
		)
	}
}
