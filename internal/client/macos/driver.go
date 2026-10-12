//go:build darwin || linux

package macos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type systemTunnelDriver struct {
	wgPath string
}

func (systemTunnelDriver) Launch(ctx context.Context, path, nameFile string) error {
	command := exec.CommandContext(ctx, path, "utun")
	command.Dir = "/"
	command.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C",
		"WG_TUN_NAME_FILE=" + nameFile,
	}

	if err := command.Run(); err != nil {
		return fmt.Errorf("start native WireGuard daemon: %w", errors.Join(err, ctx.Err()))
	}

	return nil
}

func (d systemTunnelDriver) Configure(
	ctx context.Context,
	name string,
	config wgtypes.Config,
) error {
	if !utunName.MatchString(name) || !config.ReplacePeers || config.PrivateKey == nil ||
		config.ListenPort == nil || *config.ListenPort < 1024 || *config.ListenPort > 65535 ||
		len(config.Peers) == 0 || len(config.Peers) > 64 {
		return errors.New("invalid native WireGuard replacement configuration")
	}

	var input strings.Builder
	fmt.Fprintf(
		&input,
		"[Interface]\nPrivateKey = %s\nListenPort = %d\n",
		config.PrivateKey.String(),
		*config.ListenPort,
	)
	for _, peer := range config.Peers {
		if peer.PublicKey == (wgtypes.Key{}) ||
			peer.PersistentKeepaliveInterval == nil || !peer.ReplaceAllowedIPs ||
			peer.Remove || peer.UpdateOnly || len(peer.AllowedIPs) == 0 {
			return errors.New("invalid native WireGuard peer configuration")
		}
		if peer.Endpoint != nil &&
			(peer.Endpoint.AddrPort().Addr() != netip.MustParseAddr("127.0.0.1") ||
				peer.Endpoint.Port < 1024 || peer.Endpoint.Port > 65535) {
			return errors.New("native WireGuard endpoint is outside pinned loopback scope")
		}

		prefixes := make([]string, 0, len(peer.AllowedIPs))
		for _, prefix := range peer.AllowedIPs {
			bits, total := prefix.Mask.Size()
			if total != 32 || bits == 0 || prefix.IP.To4() == nil {
				return errors.New("native WireGuard peer has unbounded allowed IPs")
			}

			prefixes = append(prefixes, prefix.String())
		}

		keepalive := *peer.PersistentKeepaliveInterval
		if keepalive < 0 || keepalive.Seconds() > 65535 ||
			keepalive.Seconds() != float64(int(keepalive.Seconds())) {
			return errors.New("invalid native WireGuard keepalive")
		}

		fmt.Fprintf(&input, "\n[Peer]\nPublicKey = %s\n", peer.PublicKey.String())
		if peer.Endpoint != nil {
			fmt.Fprintf(&input, "Endpoint = %s\n", peer.Endpoint.String())
		}

		fmt.Fprintf(
			&input,
			"AllowedIPs = %s\nPersistentKeepalive = %d\n",
			strings.Join(prefixes, ", "),
			int(keepalive.Seconds()),
		)
	}

	command := exec.CommandContext(ctx, d.wgPath, "setconf", name, "/dev/stdin")
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	command.Stdin = strings.NewReader(input.String())

	// wg's error output may quote configuration lines. Keep private stdin out
	// of process arguments, logs and the returned diagnostic.
	if err := command.Run(); err != nil {
		return fmt.Errorf("configure native WireGuard: %w", errors.Join(err, ctx.Err()))
	}

	return nil
}

func (d systemTunnelDriver) Device(ctx context.Context, name string) (*wgtypes.Device, error) {
	if !utunName.MatchString(name) {
		return nil, ErrOwnershipConflict
	}

	command := exec.CommandContext(ctx, d.wgPath, "show", name, "public-key")
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	var output boundedPublicOutput
	command.Stdout = &output

	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("inspect native WireGuard identity: %w", errors.Join(err, ctx.Err()))
	}

	text := strings.TrimSpace(output.String())
	if text == "(none)" {
		return &wgtypes.Device{Name: name}, nil
	}

	key, err := wgtypes.ParseKey(text)
	if err != nil {
		return nil, errors.New("native WireGuard returned an invalid public identity")
	}

	return &wgtypes.Device{Name: name, PublicKey: key}, nil
}

type boundedPublicOutput struct{ bytes.Buffer }

func (b *boundedPublicOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 128 {
		return 0, errors.New("native public identity output exceeds bound")
	}

	return b.Buffer.Write(data)
}
