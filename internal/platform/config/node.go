package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Node describes the shared runtime configuration for the Linux gateway and
// client executables. The two binaries intentionally share transport fields;
// role-specific behavior remains in their composition code rather than in a
// second, subtly different configuration parser.
type Node struct {
	Identity     NodeIdentity     `toml:"node"`
	Relay        NodeRelay        `toml:"relay"`
	WireGuard    NodeWireGuard    `toml:"wireguard"`
	Coordination NodeCoordination `toml:"coordination"`
	Direct       NodeDirect       `toml:"direct"`
	DNS          NodeDNS          `toml:"dns"`
}

type NodeIdentity struct {
	StatePath           string `toml:"state_path"`
	ControlURL          string `toml:"control_url"`
	EnrollmentTokenFile string `toml:"enrollment_token_file"`
	Refresh             bool   `toml:"refresh"`
	Name                string `toml:"name"`

	// Token is populated only from EnrollmentTokenFile and is never decoded
	// from TOML. Keeping it out of the serialized shape makes accidental secret
	// commits less likely and mirrors the control-plane secret-file contract.
	Token string `toml:"-"`
}

type NodeRelay struct {
	WebSocketURL      string `toml:"websocket_url"`
	UDPAddress        string `toml:"udp_address"`
	TicketFile        string `toml:"ticket_file"`
	SessionID         string `toml:"session_id"`
	DestinationDevice string `toml:"destination_device_id"`
	ListenAddress     string `toml:"listen_address"`
	WireGuardAddress  string `toml:"wireguard_address"`
	STUNServer        string `toml:"stun_server"`
	Ticket            string `toml:"-"`
}

type NodeWireGuard struct {
	InterfaceName   string `toml:"interface"`
	ListenPort      uint   `toml:"listen_port"`
	PeerPublicKey   string `toml:"peer_public_key"`
	OverlayAddress  string `toml:"overlay_address"`
	AllowedPrefixes string `toml:"allowed_prefixes"`
	Routes          string `toml:"routes"`
}

type NodeCoordination struct {
	URL               string `toml:"url"`
	RootPublicKeyFile string `toml:"root_public_key_file"`
	NetworkID         string `toml:"network_id"`
}

type NodeDirect struct {
	Candidates string `toml:"candidates"`
}

type NodeDNS struct {
	Link             string `toml:"link"`
	EnableForwarding bool   `toml:"enable_forwarding"`
}

// LoadClient reads a client TOML file and applies safe client defaults.
func LoadClient(path string) (Node, error) {
	return loadNode(path, "linux-client", "state/client.json", "127.0.0.1:51822", "127.0.0.1:51820")
}

// LoadAgent reads a gateway TOML file and applies safe gateway defaults.
func LoadAgent(path string) (Node, error) {
	return loadNode(path, "linux-gateway", "state/agent.json", "127.0.0.1:51821", "127.0.0.1:51820")
}

func loadNode(path, defaultName, defaultState, defaultBridge, defaultWireGuard string) (Node, error) {
	var cfg Node
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return Node{}, fmt.Errorf("decode node config: %w", err)
	}
	if cfg.Identity.Name == "" {
		cfg.Identity.Name = defaultName
	}
	if cfg.Identity.StatePath == "" {
		cfg.Identity.StatePath = defaultState
	}
	if cfg.Relay.ListenAddress == "" {
		cfg.Relay.ListenAddress = defaultBridge
	}
	if cfg.Relay.WireGuardAddress == "" {
		cfg.Relay.WireGuardAddress = defaultWireGuard
	}
	if cfg.WireGuard.ListenPort == 0 {
		cfg.WireGuard.ListenPort = 51820
	}
	if cfg.Coordination.NetworkID == "" {
		cfg.Coordination.NetworkID = "home"
	}
	if cfg.Identity.EnrollmentTokenFile != "" {
		value, err := readNodeSecret(cfg.Identity.EnrollmentTokenFile, "enrollment token")
		if err != nil {
			return Node{}, err
		}
		cfg.Identity.Token = value
	}
	if cfg.Relay.TicketFile != "" {
		value, err := readNodeSecret(cfg.Relay.TicketFile, "relay ticket")
		if err != nil {
			return Node{}, err
		}
		cfg.Relay.Ticket = value
	}
	return cfg, nil
}

func readNodeSecret(path, label string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	value = []byte(strings.TrimSpace(string(value)))
	if len(value) == 0 {
		return "", fmt.Errorf("%s file is empty", label)
	}
	return string(value), nil
}
