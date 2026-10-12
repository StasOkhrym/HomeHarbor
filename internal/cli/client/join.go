package client

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/platform/trust"
)

type joinOptions struct {
	controlURL  string
	caFile      string
	rootFile    string
	networkID   string
	fingerprint string
	statePath   string
}

func newJoinCommand() *cobra.Command {
	var options joinOptions
	command := &cobra.Command{
		Use:   "join",
		Short: "Join a signed HomeHarbor invitation using private stdin input",
		Args:  host.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runJoin(command, options)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.controlURL, "control", "", "HTTPS control origin")
	flags.StringVar(&options.caFile, "ca-file", "", "trusted PEM CA file for control TLS")
	flags.StringVar(
		&options.rootFile,
		"root-public-key",
		"",
		"trusted companion root public key file",
	)
	flags.StringVar(&options.networkID, "network-id", "", "expected signed network ID")
	flags.StringVar(
		&options.fingerprint,
		"trust-fingerprint",
		"",
		"out-of-band SHA-256 root and network fingerprint",
	)
	flags.StringVar(&options.statePath, "state", "", "private client state file")
	return command
}

func runJoin(command *cobra.Command, options joinOptions) (result error) {
	if err := command.Context().Err(); err != nil {
		return err
	}
	if options.controlURL == "" || options.caFile == "" || options.rootFile == "" ||
		options.networkID == "" || options.fingerprint == "" || options.statePath == "" {
		return errors.New(
			"control, CA, root public key, network ID, trust fingerprint and state are required",
		)
	}
	origin, err := url.Parse(options.controlURL)
	if err != nil || origin.Scheme != "https" || origin.Host == "" ||
		origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" {
		return errors.New("control must be an HTTPS origin without a path, query or fragment")
	}
	root, err := node.LoadPublicKeyFile(options.rootFile)
	if err != nil {
		return fmt.Errorf("load trusted root: %w", err)
	}
	if !strings.EqualFold(options.fingerprint, trustFingerprint(root, options.networkID)) {
		return errors.New("trusted root and network fingerprint do not match")
	}
	client, err := trust.NewHTTPClientFromCAFile(options.caFile)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	store, err := localstate.Open(options.statePath)
	if err != nil {
		return fmt.Errorf("open private client state: %w", err)
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	state, err := node.LoadOrCreateFrom(store)
	if err != nil {
		return fmt.Errorf("load private client state: %w", err)
	}
	if state.DeviceCredential != "" {
		return errors.New("client is already joined; use the normal run command")
	}
	deviceID, err := joinDeviceID(state.IdentityPublicKey)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(command.OutOrStdout(), "Client identity: %s\n", deviceID); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(
		command.OutOrStdout(),
		"Trust fingerprint verified. Enter the signed invitation and separate code.",
	); err != nil {
		return err
	}
	scanner := bufio.NewScanner(command.InOrStdin())
	scanner.Buffer(make([]byte, 4096), 16*1024)
	link, err := host.ReadPrivateLine(scanner, command, "Invitation link")
	if err != nil {
		return err
	}
	code, err := host.ReadPrivateLine(scanner, command, "Invitation code")
	if err != nil {
		return err
	}
	inviteURL, err := url.Parse(link)
	if err != nil || inviteURL.Scheme != origin.Scheme || inviteURL.Host != origin.Host {
		return errors.New("invitation link origin does not match trusted control")
	}
	return node.EnrollByInviteFrom(command.Context(), client, node.InviteEnrollment{
		ControlURL: options.controlURL, InviteLink: link, Code: code,
		DeviceID: deviceID, StatePath: options.statePath, RootPublicKey: root,
		NetworkID: options.networkID,
		OnStage: func(stage node.InviteStage) {
			// Status output is advisory; a closed output stream cannot roll
			// back a submitted proof or a durably claimed credential.
			switch stage {
			case node.InvitePending:
				_, _ = fmt.Fprintln(command.OutOrStdout(), "Pending companion approval.")
			case node.InviteApproved:
				_, _ = fmt.Fprintln(
					command.OutOrStdout(),
					"Approved by companion; claiming credential.",
				)
			case node.InviteClaimed:
				_, _ = fmt.Fprintln(
					command.OutOrStdout(),
					"Credential claimed. Start the normal client runtime to apply signed network state.",
				)
			}
		},
	}, &state, store)
}

// The fingerprint binds both the public signing root and the selected network
// to an independently communicated value. It never contains a private key.
func trustFingerprint(root ed25519.PublicKey, networkID string) string {
	digest := sha256.New()
	digest.Write([]byte("homeharbor/network-trust/v1\x00"))
	digest.Write(root)
	digest.Write([]byte(networkID))
	return hex.EncodeToString(digest.Sum(nil))
}

func joinDeviceID(identityPublicKey string) (string, error) {
	public, err := base64.RawURLEncoding.Strict().DecodeString(identityPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return "", errors.New("client identity public key is invalid")
	}

	digest := sha256.Sum256(public)

	return "client-" + hex.EncodeToString(digest[:12]), nil
}
