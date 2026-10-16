package node

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/node/credentials"
	controlprotocol "github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// SnapshotApplier is the only authority a node uses for local network state.
// Validation errors leave active state intact. Runtime errors may leave partial
// kernel state, but gateways must keep the tunnel denied until a complete retry.
type SnapshotApplier interface {
	Apply(context.Context, snapshot.NetworkSnapshot) error
}

// SignedSnapshotApplier receives the original envelope after lineage checks.
// Native helpers use it to independently re-verify authority before any host
// effect; legacy Linux owners continue consuming the decoded value.
type SignedSnapshotApplier interface {
	ApplySigned(context.Context, snapshot.Envelope, snapshot.NetworkSnapshot) error
}

// SnapshotRestoreVerifier defers host reconstruction until the current
// authenticated head arrives. Its checkpoint is a lineage anchor, while a
// separate privileged owner may already have accepted a newer signed policy.
type SnapshotRestoreVerifier interface {
	VerifyRestore(context.Context, snapshot.Envelope, snapshot.NetworkSnapshot) error
}

func applyVerifiedSnapshot(
	ctx context.Context,
	applier SnapshotApplier,
	envelope snapshot.Envelope,
	value snapshot.NetworkSnapshot,
	telemetry *RuntimeTelemetry,
) error {
	var err error

	if signed, ok := applier.(SignedSnapshotApplier); ok {
		err = signed.ApplySigned(ctx, envelope, value)
	} else {
		err = applier.Apply(ctx, value)
	}

	if telemetry != nil {
		if err != nil {
			telemetry.Failed()
		} else {
			telemetry.Applied(value)
		}
	}

	return err
}

// PreparedSnapshotApplier validates without mutating runtime state, then applies
// under the gateway's deny guard. Dependencies are explicit, not discovered by
// runtime assertions on an Apply-only interface.
type PreparedSnapshotApplier interface {
	SnapshotApplier
	Prepare(context.Context, snapshot.NetworkSnapshot) error
}

// CompositeSnapshotApplier serializes multi-owner changes. It releases a gateway
// guard only after every owner succeeds; this is fail-closed, not a claim of an
// atomic transaction across WireGuard, nftables, routing and systemd-resolved.
type CompositeSnapshotApplier struct {
	mu         sync.Mutex
	guard      StagedSnapshotApplier
	components []PreparedSnapshotApplier
}

// NewCompositeSnapshotApplier accepts a nil guard for a non-forwarding client.
// Nil owners are errors at Apply; silently filtering them hides broken wiring.
func NewCompositeSnapshotApplier(
	guard StagedSnapshotApplier,
	components ...PreparedSnapshotApplier,
) *CompositeSnapshotApplier {
	return &CompositeSnapshotApplier{
		guard:      guard,
		components: append([]PreparedSnapshotApplier(nil), components...),
	}
}

func (a *CompositeSnapshotApplier) Apply(
	ctx context.Context,
	value snapshot.NetworkSnapshot,
) error {
	if a == nil || (a.guard == nil && len(a.components) == 0) {
		return errors.New("snapshot applier has no components")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, component := range a.components {
		if component == nil {
			return errors.New("nil snapshot owner")
		}
	}

	if a.guard != nil {
		if err := a.guard.Prepare(ctx, value); err != nil {
			return err
		}
	}

	for _, component := range a.components {
		if err := component.Prepare(ctx, value); err != nil {
			return err
		}
	}

	if a.guard != nil {
		if err := a.guard.Guard(ctx, value); err != nil {
			return err
		}

		if err := a.guard.ApplyPrepared(ctx, value); err != nil {
			return err
		}
	}

	for _, component := range a.components {
		if err := component.Apply(ctx, value); err != nil {
			return err
		}
	}

	if a.guard != nil {
		return a.guard.Commit(ctx, value)
	}

	return nil
}

type CoordinationConfig struct {
	URL           string
	HTTPClient    *http.Client
	Credential    string
	Leases        credentials.LeaseSource
	DeviceID      string
	NetworkID     string
	RootPublicKey ed25519.PublicKey
	// StatePath optionally stores the last applied signed envelope. The root
	// key and network remain provisioned configuration, never downloaded state.
	StatePath        string
	HeartbeatEvery   time.Duration
	ReconnectInitial time.Duration
	ReconnectMax     time.Duration
	CandidateHandler func(context.Context, controlprotocol.CandidateUpdate) error
	// CandidateProvider supplies local endpoint candidates after each
	// coordination reconnect and heartbeat. The authenticated server enriches
	// each update with the sender identity before forwarding it to the peer.
	CandidateProvider func(context.Context) ([]controlprotocol.CandidateUpdate, error)
	// CandidateChanges lets a transport wake coordination as soon as a new
	// relay-observed endpoint is available. Heartbeats remain the fallback for
	// providers that do not have an event source.
	CandidateChanges <-chan struct{}
	Telemetry        *RuntimeTelemetry
}

// RunCoordinationLoop keeps the last verified gateway state active while the
// control connection is unavailable. A reconnect never resets the revision
// cursor; the next snapshot must still pass the normal contiguous-chain check.
func RunCoordinationLoop(
	ctx context.Context,
	cfg CoordinationConfig,
	applier SnapshotApplier,
) error {
	initial := cfg.ReconnectInitial
	if initial <= 0 {
		initial = time.Second
	}

	maximum := cfg.ReconnectMax
	if maximum < initial {
		maximum = 30 * time.Second
	}

	backoff := initial

	cursor, err := restoreSnapshotCursor(ctx, cfg, applier)
	if err != nil {
		return err
	}

	for {
		err := runCoordination(ctx, cfg, applier, &cursor)
		if errors.Is(err, ErrSnapshotState) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return nil
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}

			return nil
		case <-timer.C:
		}

		backoff = min(backoff*2, maximum)
	}
}

// LoadPublicKeyFile accepts the raw 32-byte or base64url form used by TOML and
// secret-file deployments. It refuses every other length so a truncated root
// key cannot accidentally turn into a different trust anchor.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	value = []byte(strings.TrimSpace(string(value)))
	if len(value) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), value...)), nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(string(value))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("root public key must be 32 raw or base64url bytes")
	}

	return ed25519.PublicKey(decoded), nil
}

type coordinationCursor struct {
	revision   uint64
	hash       []byte
	needsApply bool
}

func runCoordination(
	ctx context.Context,
	cfg CoordinationConfig,
	applier SnapshotApplier,
	cursor *coordinationCursor,
) error {
	var admitted controlprotocol.CredentialLease
	if cfg.Leases != nil {
		var err error

		admitted, err = cfg.Leases.Current(ctx)
		if err != nil {
			return err
		}
		if admitted.DeviceID != cfg.DeviceID || !admitted.ExpiresAt.After(time.Now()) {
			return errors.New("invalid coordination lease")
		}

		cfg.Credential = admitted.Credential
	}

	if cfg.URL == "" || cfg.Credential == "" || cfg.DeviceID == "" || cfg.NetworkID == "" ||
		len(cfg.RootPublicKey) != ed25519.PublicKeySize ||
		applier == nil {
		return errors.New(
			"coordination URL, credentials, device, network, root key, and applier are required",
		)
	}

	sessionContext, sessionCancel := context.WithCancel(ctx)
	if cfg.Leases != nil {
		sessionCancel()
		sessionContext, sessionCancel = context.WithDeadline(ctx, admitted.ExpiresAt)
	}
	defer sessionCancel()

	header := make(http.Header)
	header.Set("Authorization", "Bearer "+cfg.Credential)

	connection, _, err := websocket.Dial(
		sessionContext,
		cfg.URL,
		&websocket.DialOptions{
			HTTPClient: cfg.HTTPClient, HTTPHeader: header,
			CompressionMode: websocket.CompressionDisabled,
		},
	)
	if err != nil {
		return fmt.Errorf("dial coordination: %w", err)
	}
	defer func() { _ = connection.CloseNow() }()

	if cfg.Leases != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)

			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-sessionContext.Done():
					return
				case <-ticker.C:
					current, err := cfg.Leases.Current(sessionContext)
					if err != nil || current != admitted {
						sessionCancel()
						return
					}
				}
			}
		}()
		defer func() { sessionCancel(); <-done }()
	}

	connection.SetReadLimit(64 << 10)

	writeMu := sync.Mutex{}
	write := func(value any) error {
		if cfg.Leases != nil {
			current, err := cfg.Leases.Current(sessionContext)
			if err != nil {
				return err
			}
			if current != admitted {
				sessionCancel()
				return errors.New("coordination lease replaced")
			}
		}

		writeMu.Lock()
		defer writeMu.Unlock()

		writeContext, cancel := context.WithTimeout(sessionContext, 10*time.Second)
		defer cancel()

		return wsjson.Write(writeContext, connection, value)
	}
	capabilities := []string{
		controlprotocol.CapabilityUDPPair,
		controlprotocol.CapabilitySplitDNS,
	}
	if cfg.Telemetry != nil {
		capabilities = append(capabilities, controlprotocol.CapabilityTelemetry)
	}

	if cfg.CandidateProvider != nil || cfg.CandidateHandler != nil {
		// Candidate exchange is opt-in. Advertising it only when both the
		// caller and its peer understand the feature keeps older nodes on the
		// relay path instead of silently sending them unsupported messages.
		capabilities = append(capabilities, controlprotocol.CapabilityDirectUDP)
	}

	hello := controlprotocol.Hello{
		Versions:     []uint16{controlprotocol.CurrentVersion},
		Capabilities: capabilities,
		DeviceID:     cfg.DeviceID,
	}
	if err := write(hello); err != nil {
		return fmt.Errorf("send coordination hello: %w", err)
	}

	var welcome controlprotocol.Welcome
	welcomeContext, cancel := context.WithTimeout(sessionContext, 10*time.Second)
	err = wsjson.Read(welcomeContext, connection, &welcome)
	cancel()
	if err != nil {
		return fmt.Errorf("read coordination welcome: %w", err)
	}
	if welcome.Type != "welcome" || welcome.Protocol.Version != controlprotocol.CurrentVersion ||
		!welcome.Protocol.Has(controlprotocol.CapabilityUDPPair) {
		return errors.New("coordination protocol negotiation failed")
	}
	if (cfg.CandidateProvider != nil || cfg.CandidateHandler != nil) &&
		!welcome.Protocol.Has(controlprotocol.CapabilityDirectUDP) {
		return errors.New("direct UDP capability was not negotiated")
	}

	sendCandidates := func() error {
		if cfg.CandidateProvider == nil {
			return nil
		}

		updates, err := cfg.CandidateProvider(sessionContext)
		if err != nil {
			return fmt.Errorf("build candidate updates: %w", err)
		}

		for _, update := range updates {
			if err := update.Validate(); err != nil {
				return fmt.Errorf("validate local candidate update: %w", err)
			}

			payload, err := json.Marshal(update)
			if err != nil {
				return fmt.Errorf("encode candidate update: %w", err)
			}

			if err := write(
				controlprotocol.Message{Type: "candidate.update", Payload: payload},
			); err != nil {
				return fmt.Errorf("send candidate update: %w", err)
			}
		}

		return nil
	}
	if err := sendCandidates(); err != nil {
		return err
	}

	heartbeatEvery := cfg.HeartbeatEvery
	if heartbeatEvery <= 0 {
		heartbeatEvery = 30 * time.Second
	}

	heartbeat := time.NewTicker(heartbeatEvery)
	defer heartbeat.Stop()

	candidateChanges := cfg.CandidateChanges
	publisherDone := make(chan struct{})
	go func() {
		defer close(publisherDone)

		runCandidatePublisher(sessionContext, heartbeat.C, candidateChanges, write, sendCandidates)
	}()
	defer func() {
		sessionCancel()
		_ = connection.CloseNow()
		<-publisherDone
	}()

	if cfg.Telemetry != nil && welcome.Protocol.Has(controlprotocol.CapabilityTelemetry) &&
		welcome.TelemetryGeneration > 0 {
		telemetryTicks := time.NewTicker(controlprotocol.TelemetryReportInterval)
		telemetryDone := make(chan struct{})
		go func() {
			defer close(telemetryDone)

			runTelemetryPublisher(
				sessionContext,
				welcome.TelemetryGeneration,
				cfg.Telemetry,
				telemetryTicks.C,
				func(value any) error {
					err := write(value)
					if err != nil {
						sessionCancel()
					}

					return err
				},
			)
		}()
		defer func() { sessionCancel(); _ = connection.CloseNow(); <-telemetryDone; telemetryTicks.Stop() }()
	}

	for {
		readContext, readCancel := context.WithTimeout(sessionContext, 2*time.Minute)
		var message controlprotocol.Message

		err = wsjson.Read(readContext, connection, &message)
		readCancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf("read coordination message: %w", err)
		}

		switch message.Type {
		case "network.snapshot":
			var envelope snapshot.Envelope

			if err := json.Unmarshal(message.Payload, &envelope); err != nil {
				return fmt.Errorf("decode network snapshot envelope: %w", err)
			}

			if err := reconcileSnapshotHead(
				sessionContext,
				cfg,
				applier,
				cursor,
				envelope,
			); err != nil {
				return err
			}
		case "heartbeat.ack":
			// The read deadline is refreshed by the next successful message.
		default:
			if message.Type == "candidate.update" {
				if cfg.CandidateHandler == nil {
					return errors.New("candidate update received without a handler")
				}

				var update controlprotocol.CandidateUpdate

				if err := json.Unmarshal(message.Payload, &update); err != nil {
					return fmt.Errorf("decode candidate update: %w", err)
				}

				if err := update.Validate(); err != nil {
					return fmt.Errorf("validate candidate update: %w", err)
				}

				if err := cfg.CandidateHandler(sessionContext, update); err != nil {
					return fmt.Errorf("handle candidate update: %w", err)
				}

				continue
			}

			return fmt.Errorf("unsupported coordination message %q", message.Type)
		}
	}
}

// runCandidatePublisher owns the periodic coordination writes for one
// authenticated WebSocket session. It must use sessionContext rather than the
// node's parent context: a reconnect cancels the old session before creating a
// new publisher, otherwise every control outage leaks a goroutine that keeps
// trying to write through a closed socket.
func runCandidatePublisher(
	ctx context.Context,
	heartbeats <-chan time.Time,
	candidateChanges <-chan struct{},
	write func(any) error,
	sendCandidates func() error,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeats:
			_ = write(controlprotocol.Message{Type: "heartbeat"})
			_ = sendCandidates()
		case _, ok := <-candidateChanges:
			if !ok {
				candidateChanges = nil
				continue
			}

			_ = sendCandidates()
		}
	}
}
