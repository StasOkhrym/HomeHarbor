package config

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

	// Token is populated from the selected file or an explicit CLI flag; it is
	// never decoded from TOML. Keeping it out of the serialized shape reduces
	// the chance of accidental secret commits.
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
func LoadClient(source Sources) (Node, error) {
	return loadNode(source, DefaultClient())
}

// LoadAgent reads a gateway TOML file and applies safe gateway defaults.
func LoadAgent(source Sources) (Node, error) {
	return loadNode(source, DefaultAgent())
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

func loadNode(source Sources, cfg Node) (Node, error) {
	fileKeys, err := readFileStrict(source.File, &cfg)
	if err != nil {
		return Node{}, err
	}

	// Token and Ticket are not TOML fields. Their explicit CLI forms participate
	// in selection without widening the on-disk secret schema.
	flags := source.Flags
	withoutInline := make(map[string]string, len(flags))
	for key, value := range flags {
		switch key {
		case "node.token":
			cfg.Identity.Token = value
		case "relay.ticket":
			cfg.Relay.Ticket = value
		default:
			withoutInline[key] = value
		}
	}

	source.Flags = withoutInline

	envKeys, flagKeys, err := applySources(&cfg, source)
	if err != nil {
		return Node{}, err
	}

	if _, ok := flags["node.token"]; ok {
		flagKeys["node.token"] = true
	}

	if _, ok := flags["relay.ticket"]; ok {
		flagKeys["relay.ticket"] = true
	}

	if err := selectedSecret(&cfg.Identity.Token, cfg.Identity.EnrollmentTokenFile,
		"node.token", "node.enrollment_token_file", fileKeys, envKeys, flagKeys); err != nil {
		return Node{}, err
	}

	if err := selectedSecret(&cfg.Relay.Ticket, cfg.Relay.TicketFile,
		"relay.ticket", "relay.ticket_file", fileKeys, envKeys, flagKeys); err != nil {
		return Node{}, err
	}

	if err := cfg.Runtime.Validate(); err != nil {
		return Node{}, err
	}

	return cfg, nil
}
