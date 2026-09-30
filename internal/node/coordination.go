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

	controlprotocol "github.com/sokhrym/go-tunnels/internal/protocol"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

// SnapshotApplier is the only authority a node uses for local network state.
// Implementations must apply atomically and retain their previous state when
// this callback returns an error.
type SnapshotApplier interface {
	Apply(context.Context, snapshot.NetworkSnapshot) error
}

type CoordinationConfig struct {
	URL            string
	Credential     string
	DeviceID       string
	NetworkID      string
	RootPublicKey  ed25519.PublicKey
	HeartbeatEvery time.Duration
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
	if cfg.URL == "" || cfg.Credential == "" || cfg.DeviceID == "" || cfg.NetworkID == "" || len(cfg.RootPublicKey) != ed25519.PublicKeySize || applier == nil {
		return errors.New("coordination URL, credentials, device, network, root key, and applier are required")
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+cfg.Credential)
	connection, _, err := websocket.Dial(ctx, cfg.URL, &websocket.DialOptions{HTTPHeader: header, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return fmt.Errorf("dial coordination: %w", err)
	}
	defer func() { _ = connection.CloseNow() }()
	connection.SetReadLimit(64 << 10)

	writeMu := sync.Mutex{}
	write := func(value any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		writeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return wsjson.Write(writeContext, connection, value)
	}
	hello := controlprotocol.Hello{Versions: []uint16{controlprotocol.CurrentVersion}, Capabilities: []string{controlprotocol.CapabilityRelay, controlprotocol.CapabilitySplitDNS}, DeviceID: cfg.DeviceID}
	if err := write(hello); err != nil {
		return fmt.Errorf("send coordination hello: %w", err)
	}
	var welcome struct {
		Type     string                     `json:"type"`
		Protocol controlprotocol.Negotiated `json:"protocol"`
	}
	welcomeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = wsjson.Read(welcomeContext, connection, &welcome)
	cancel()
	if err != nil {
		return fmt.Errorf("read coordination welcome: %w", err)
	}
	if welcome.Type != "welcome" || welcome.Protocol.Version != controlprotocol.CurrentVersion || !welcome.Protocol.Has(controlprotocol.CapabilityRelay) {
		return errors.New("coordination protocol negotiation failed")
	}

	heartbeatEvery := cfg.HeartbeatEvery
	if heartbeatEvery <= 0 {
		heartbeatEvery = 30 * time.Second
	}
	heartbeat := time.NewTicker(heartbeatEvery)
	defer heartbeat.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.C:
				_ = write(controlprotocol.Message{Type: "heartbeat"})
			}
		}
	}()

	var revision uint64
	var previousHash []byte
	for {
		readContext, readCancel := context.WithTimeout(ctx, 2*time.Minute)
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
			if err := snapshot.VerifyNext(envelope, cfg.RootPublicKey, cfg.NetworkID, revision, previousHash); err != nil {
				return fmt.Errorf("verify network snapshot: %w", err)
			}
			value, err := snapshot.Decode(envelope)
			if err != nil {
				return fmt.Errorf("decode verified network snapshot: %w", err)
			}
			if err := applier.Apply(ctx, value); err != nil {
				return fmt.Errorf("apply network snapshot revision %d: %w", value.Revision, err)
			}
			revision = value.Revision
			previousHash = append(previousHash[:0], envelope.Hash...)
		case "heartbeat.ack":
			// The read deadline is refreshed by the next successful message.
		default:
			if strings.HasPrefix(message.Type, "candidate.") {
				continue
			}
			return fmt.Errorf("unsupported coordination message %q", message.Type)
		}
	}
}
