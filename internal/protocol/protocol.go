package protocol

import (
	"encoding/json"
	"slices"
	"sync"
)

const CurrentVersion uint16 = 1
const (
	CapabilityRelay     = "relay-v1"
	CapabilityDirectUDP = "direct-udp-v1"
	CapabilitySplitDNS  = "split-dns-v1"
)
const ErrorUpgradeRequired = "upgrade_required"

type Hello struct {
	Versions     []uint16 `json:"versions"`
	Capabilities []string `json:"capabilities"`
	DeviceID     string   `json:"device_id,omitempty"`
}
type Negotiated struct {
	Version      uint16   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

func (n Negotiated) Has(capability string) bool { return slices.Contains(n.Capabilities, capability) }

type ProtocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ProtocolError) Error() string { return e.Code + ": " + e.Message }
func Negotiate(hello Hello) (Negotiated, *ProtocolError) {
	if !slices.Contains(hello.Versions, CurrentVersion) {
		return Negotiated{}, &ProtocolError{Code: ErrorUpgradeRequired, Message: "client does not support protocol version 1"}
	}
	if !slices.Contains(hello.Capabilities, CapabilityRelay) {
		return Negotiated{}, &ProtocolError{Code: ErrorUpgradeRequired, Message: "relay-v1 capability is required"}
	}
	supported := []string{CapabilityRelay}
	for _, c := range []string{CapabilityDirectUDP, CapabilitySplitDNS} {
		if slices.Contains(hello.Capabilities, c) {
			supported = append(supported, c)
		}
	}
	return Negotiated{Version: CurrentVersion, Capabilities: supported}, nil
}

type CandidateType string

const (
	CandidateHost            CandidateType = "host"
	CandidateServerReflexive CandidateType = "server_reflexive"
	CandidateRelay           CandidateType = "relay"
)

type Candidate struct {
	Type     CandidateType `json:"type"`
	Address  string        `json:"address"`
	Priority uint32        `json:"priority"`
}
type Message struct {
	Type     string          `json:"type"`
	Revision uint64          `json:"revision,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

type Path string

const (
	PathRelay  Path = "relay"
	PathDirect Path = "direct"
)

type PathSelector struct {
	mu      sync.RWMutex
	current Path
}

func NewPathSelector() *PathSelector  { return &PathSelector{current: PathRelay} }
func (s *PathSelector) Current() Path { s.mu.RLock(); defer s.mu.RUnlock(); return s.current }

func (s *PathSelector) DirectHandshakeSucceeded() { s.mu.Lock(); s.current = PathDirect; s.mu.Unlock() }

func (s *PathSelector) DirectFailed() { s.mu.Lock(); s.current = PathRelay; s.mu.Unlock() }
