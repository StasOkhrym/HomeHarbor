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

	controlprotocol "github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// SnapshotApplier is the only authority a node uses for local network state.
// Validation errors leave active state intact. Runtime errors may leave partial
// kernel state, but gateways must keep the tunnel denied until a complete retry.
type SnapshotApplier interface {
	Apply(context.Context, snapshot.NetworkSnapshot) error
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
	Credential    string
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

// RunCoordination maintains the authenticated control WebSocket and verifies
// every snapshot before applying it. A reconnect should call this function
// again; it intentionally does not invent a snapshot during control outage.
func RunCoordination(ctx context.Context, cfg CoordinationConfig, applier SnapshotApplier) error {
	cursor, err := restoreSnapshotCursor(ctx, cfg, applier)
	if err != nil {
		return err
	}
	return runCoordination(ctx, cfg, applier, &cursor)
}

type coordinationCursor struct {
	revision uint64
	hash     []byte
}

func runCoordination(
	ctx context.Context,
	cfg CoordinationConfig,
	applier SnapshotApplier,
	cursor *coordinationCursor,
) error {
	if cfg.URL == "" || cfg.Credential == "" || cfg.DeviceID == "" || cfg.NetworkID == "" ||
		len(cfg.RootPublicKey) != ed25519.PublicKeySize ||
		applier == nil {
		return errors.New(
			"coordination URL, credentials, device, network, root key, and applier are required",
		)
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+cfg.Credential)
	connection, _, err := websocket.Dial(
		ctx,
		cfg.URL,
		&websocket.DialOptions{HTTPHeader: header, CompressionMode: websocket.CompressionDisabled},
	)
	if err != nil {
		return fmt.Errorf("dial coordination: %w", err)
	}
	defer func() { _ = connection.CloseNow() }()
	sessionContext, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()
	connection.SetReadLimit(64 << 10)

	writeMu := sync.Mutex{}
	write := func(value any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		writeContext, cancel := context.WithTimeout(sessionContext, 10*time.Second)
		defer cancel()
		return wsjson.Write(writeContext, connection, value)
	}
	capabilities := []string{
		controlprotocol.CapabilityRelay,
		controlprotocol.CapabilityUDPPairV2,
		controlprotocol.CapabilitySplitDNS,
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
	var welcome struct {
		Type     string                     `json:"type"`
		Protocol controlprotocol.Negotiated `json:"protocol"`
	}
	welcomeContext, cancel := context.WithTimeout(sessionContext, 10*time.Second)
	err = wsjson.Read(welcomeContext, connection, &welcome)
	cancel()
	if err != nil {
		return fmt.Errorf("read coordination welcome: %w", err)
	}
	if welcome.Type != "welcome" || welcome.Protocol.Version != controlprotocol.CurrentVersion ||
		(!welcome.Protocol.Has(controlprotocol.CapabilityRelay) && !welcome.Protocol.Has(controlprotocol.CapabilityUDPPairV2)) {
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
			if err := reconcileSnapshotHead(ctx, cfg, applier, cursor, envelope); err != nil {
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
				if err := cfg.CandidateHandler(ctx, update); err != nil {
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
