package node

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// PeerStatistics has no representation for private keys, preshared keys or raw
// WireGuard configuration. Readers expose only the owned interface's public stats.
type PeerStatistics struct {
	RXBytes           uint64
	TXBytes           uint64
	LastHandshakeUnix int64
	Endpoint          string
}

type PublicStatisticsReader interface {
	Read(context.Context) (map[string]PeerStatistics, error)
}

type TelemetryConfig struct {
	DeviceID     string
	Role         string
	Statistics   PublicStatisticsReader
	PathDeviceID string
	SelectedPath func() protocol.Path
	PathChanges  func() <-chan struct{}
}

type RuntimeTelemetry struct {
	cfg       TelemetryConfig
	runtimeID string
	mu        sync.RWMutex
	state     protocol.RuntimeState
	revision  uint64
	peers     map[string]string
	changed   chan struct{}
}

func NewRuntimeTelemetry(cfg TelemetryConfig) (*RuntimeTelemetry, error) {
	if cfg.DeviceID == "" || (cfg.Role != "client" && cfg.Role != "gateway") {
		return nil, errors.New("runtime telemetry requires a device and role")
	}

	return &RuntimeTelemetry{
		cfg:       cfg,
		runtimeID: uuid.NewString(),
		state:     protocol.RuntimeStarting,
		changed:   make(chan struct{}),
		peers:     map[string]string{},
	}, nil
}

// Applied is called only after the real signed network owner successfully
// completes an apply. A control reconnect alone never changes runtime identity.
func (r *RuntimeTelemetry) Applied(value snapshot.NetworkSnapshot) {
	configured, err := BuildWireGuardPeerConfigs(value, r.cfg.DeviceID)
	peers := map[string]string{}
	state := protocol.RuntimeRunning
	if errors.Is(err, ErrLocalDeviceMissing) {
		state = protocol.RuntimeStopped
	}

	if err == nil {
		for _, peer := range configured {
			for _, device := range value.Devices {
				if peer.PublicKey == device.WireGuardPublicKey {
					peers[peer.PublicKey] = device.ID
					break
				}
			}
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.peers, r.state, r.revision = peers, state, value.Revision
	r.notifyLocked()
}

func (r *RuntimeTelemetry) Failed() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.state = protocol.RuntimeFailed
	r.notifyLocked()
}

// Stopped must be called by the runtime owner after its cleanup has completed.
// Cancellation or a disconnected control socket is never sufficient evidence.
func (r *RuntimeTelemetry) Stopped() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.state = protocol.RuntimeStopped
	r.peers = map[string]string{}
	r.notifyLocked()
}

func (r *RuntimeTelemetry) Changes() <-chan struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.changed
}

func (r *RuntimeTelemetry) PathChanges() <-chan struct{} {
	if r.cfg.PathChanges != nil {
		return r.cfg.PathChanges()
	}

	return nil
}
func (r *RuntimeTelemetry) notifyLocked() { close(r.changed); r.changed = make(chan struct{}) }

func (r *RuntimeTelemetry) Snapshot(ctx context.Context) (protocol.TelemetryReport, error) {
	if err := ctx.Err(); err != nil {
		return protocol.TelemetryReport{}, err
	}

	r.mu.RLock()
	state, revision, peers := r.state, r.revision, r.peers
	r.mu.RUnlock()
	self := protocol.PeerObservation{DeviceID: r.cfg.DeviceID}
	report := protocol.TelemetryReport{
		RuntimeID:       r.runtimeID,
		State:           state,
		AppliedRevision: revision,
		Observations:    []protocol.PeerObservation{self},
	}
	if r.cfg.Statistics == nil || revision == 0 ||
		len(peers) >= protocol.MaxTelemetryObservations ||
		state == protocol.RuntimeStarting ||
		state == protocol.RuntimeStopped {
		return report, nil
	}

	stats, err := r.cfg.Statistics.Read(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return protocol.TelemetryReport{}, ctx.Err()
		}

		return report, nil
	}

	keys := make([]string, 0, len(peers))
	for key := range peers {
		keys = append(keys, key)
	}

	slices.SortFunc(keys, func(a, b string) int { return strings.Compare(peers[a], peers[b]) })
	self.CountersAvailable = true
	for _, key := range keys {
		sample, ok := stats[key]
		if !ok {
			self.CountersAvailable = false
			continue
		}
		if sample.RXBytes > math.MaxInt64 || sample.TXBytes > math.MaxInt64 ||
			sample.LastHandshakeUnix < 0 {
			self.CountersAvailable = false
			continue
		}

		if self.RXBytes > math.MaxInt64-sample.RXBytes ||
			self.TXBytes > math.MaxInt64-sample.TXBytes {
			self.CountersAvailable = false
		} else {
			self.RXBytes += sample.RXBytes
			self.TXBytes += sample.TXBytes
		}

		observation := protocol.PeerObservation{
			DeviceID:          peers[key],
			CountersAvailable: true,
			RXBytes:           sample.RXBytes,
			TXBytes:           sample.TXBytes,
			LastHandshakeUnix: sample.LastHandshakeUnix,
			Endpoint:          sample.Endpoint,
		}
		if peers[key] == r.cfg.PathDeviceID && r.cfg.SelectedPath != nil {
			observation.Path = r.cfg.SelectedPath()
		}

		if r.cfg.Role == "gateway" {
			report.Observations = append(report.Observations, observation)
		} else {
			if sample.LastHandshakeUnix > self.LastHandshakeUnix {
				self.LastHandshakeUnix = sample.LastHandshakeUnix
			}

			if len(peers) == 1 || peers[key] == r.cfg.PathDeviceID {
				self.Endpoint = observation.Endpoint
				self.Path = observation.Path
			}
		}
	}

	if !self.CountersAvailable {
		self.RXBytes, self.TXBytes = 0, 0
	}

	report.Observations[0] = self

	return report, nil
}
