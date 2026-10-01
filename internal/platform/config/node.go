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
	Runtime      Runtime          `toml:"runtime"`
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
	return loadNode(path, DefaultClient())
}

// LoadAgent reads a gateway TOML file and applies safe gateway defaults.
func LoadAgent(path string) (Node, error) {
	return loadNode(path, DefaultAgent())
}

// DefaultClient is shared by flags and TOML loading to keep precedence stable.
func DefaultClient() Node {
	return Node{
		Runtime:  DefaultRuntime(false),
		Identity: NodeIdentity{Name: "linux-client", StatePath: "state/client.json"},
		Relay: NodeRelay{
			ListenAddress:    "127.0.0.1:51822",
			WireGuardAddress: "127.0.0.1:51820",
		},
		WireGuard:    NodeWireGuard{ListenPort: 51820},
		Coordination: NodeCoordination{NetworkID: "home"},
	}
}

// DefaultAgent changes only role-specific defaults, not transport semantics.
func DefaultAgent() Node {
	cfg := DefaultClient()
	cfg.Identity.Name = "linux-gateway"
	cfg.Identity.StatePath = "state/agent.json"
	cfg.Relay.ListenAddress = "127.0.0.1:51821"

	return cfg
}

func loadNode(path string, cfg Node) (Node, error) {
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return Node{}, fmt.Errorf("decode node config: %w", err)
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
	if err := cfg.Runtime.Validate(); err != nil {
		return Node{}, err
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
