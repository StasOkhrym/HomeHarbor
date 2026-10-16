package node

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

const maxPublicStatisticsBytes = 64 << 10

var statisticsInterfaceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)

type (
	WireGuardStatisticsCommand func(context.Context, string, string) ([]byte, error)
	WireGuardStatistics        struct {
		name string
		run  WireGuardStatisticsCommand
	}
)

func NewWireGuardStatistics(
	name string,
	run WireGuardStatisticsCommand,
) (*WireGuardStatistics, error) {
	if !statisticsInterfaceName.MatchString(name) {
		return nil, errors.New("invalid statistics interface")
	}

	if run == nil {
		run = runPublicWireGuardField
	}

	return &WireGuardStatistics{name: name, run: run}, nil
}

func (r *WireGuardStatistics) Read(ctx context.Context) (map[string]PeerStatistics, error) {
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	peers := map[string]PeerStatistics{}
	for _, field := range []string{"transfer", "latest-handshakes", "endpoints"} {
		if err := operation.Err(); err != nil {
			return nil, err
		}

		data, err := r.run(operation, r.name, field)
		if err != nil {
			if operation.Err() != nil {
				return nil, operation.Err()
			}

			return nil, errors.New("read public WireGuard statistics failed")
		}
		if len(data) > maxPublicStatisticsBytes || parseWireGuardField(field, data, peers) != nil {
			return nil, errors.New("invalid public WireGuard statistics")
		}
	}

	return peers, nil
}

func parseWireGuardField(field string, data []byte, peers map[string]PeerStatistics) error {
	invalid := errors.New("invalid public statistics field")
	seen := map[string]bool{}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil
	}

	lines := strings.Split(text, "\n")
	if len(lines) > protocol.MaxTelemetryObservations {
		return invalid
	}

	for _, line := range lines {
		parts := strings.Fields(line)
		columns := 2
		if field == "transfer" {
			columns = 3
		}

		if len(parts) != columns {
			return invalid
		}

		key, err := wgtypes.ParseKey(parts[0])
		if err != nil || key == (wgtypes.Key{}) || key.String() != parts[0] || seen[parts[0]] {
			return invalid
		}

		seen[parts[0]] = true
		sample, exists := peers[parts[0]]
		switch field {
		case "transfer":
			rx, rxErr := strconv.ParseUint(parts[1], 10, 64)

			tx, txErr := strconv.ParseUint(parts[2], 10, 64)
			if rxErr != nil || txErr != nil || rx > math.MaxInt64 || tx > math.MaxInt64 {
				return invalid
			}

			sample.RXBytes, sample.TXBytes = rx, tx
		case "latest-handshakes":
			value, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || value < 0 {
				return invalid
			}
			if !exists {
				continue
			}

			sample.LastHandshakeUnix = value
		case "endpoints":
			endpoint := ""
			if parts[1] != "(none)" {
				value, err := netip.ParseAddrPort(parts[1])
				if err != nil || value.Port() == 0 || value.Addr().IsUnspecified() ||
					value.Addr().IsMulticast() ||
					value.Addr().Zone() != "" {
					return invalid
				}

				endpoint = value.String()
			}

			if !exists {
				continue
			}

			sample.Endpoint = endpoint
		default:
			return invalid
		}

		peers[parts[0]] = sample
	}

	return nil
}

func runPublicWireGuardField(ctx context.Context, name, field string) ([]byte, error) {
	// Never use dump, showconf, private-key or preshared-keys: their output has
	// secret-bearing representations even if a later parser discards a line.
	switch field {
	case "transfer", "latest-handshakes", "endpoints":
	default:
		return nil, errors.New("unsupported public statistics field")
	}

	command := exec.CommandContext(ctx, "wg", "show", name, field)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "WG_HIDE_KEYS=always"}
	command.WaitDelay = time.Second
	var output boundedStatisticsOutput
	command.Stdout = &output

	if err := command.Run(); err != nil {
		return nil, errors.New("public WireGuard query failed")
	}

	return output.Bytes(), nil
}

type boundedStatisticsOutput struct{ bytes.Buffer }

func (b *boundedStatisticsOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > maxPublicStatisticsBytes {
		return 0, errors.New("public statistics output exceeds bound")
	}

	return b.Buffer.Write(data)
}
