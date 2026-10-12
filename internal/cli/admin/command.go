// Package admin adapts trusted companion operations to the shared CLI host.
package admin

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/companion"
	platformconfig "github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/trust"
)

type options struct {
	config, key, passphraseFile, endpoint, caFile, keyID string
	manifest, network, profile, baseURL, invite          string
	overlayPool, device                                  string
	ttl                                                  time.Duration
}

// NewCommand constructs a fresh tree. It does no file, key or network I/O.
func NewCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "admin",
		Short: "Manage HomeHarbor trusted companion keys and invites",
		Args:  host.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return host.ExactArgs(1)(cmd, args)
		},
	}
	root.AddCommand(
		newInitRoot(), newInitSnapshot(), newInvite(),
		newApprove(), newPublishSnapshot(), newRevokeDevice(),
	)
	return root
}

func common(cmd *cobra.Command, o *options) {
	cmd.Flags().StringVar(&o.config, "config", "", "admin TOML configuration path")
	cmd.Flags().StringVar(&o.key, "key", "state/root-key.age", "encrypted root key path")
	cmd.Flags().
		StringVar(&o.passphraseFile, "passphrase-file", "", "file containing the passphrase")
}

func remote(cmd *cobra.Command, o *options) {
	cmd.Flags().StringVar(&o.endpoint, "endpoint", "https://control.example", "control plane URL")
	cmd.Flags().StringVar(&o.caFile, "ca-file", "", "explicit PEM CA for the control endpoint")
}

func remoteApprover(o options) (companion.RemoteApprover, func(), error) {
	a := companion.RemoteApprover{Endpoint: o.endpoint, KeyID: o.keyID}
	if o.caFile == "" {
		return a, func() {}, nil
	}

	endpoint, err := url.Parse(o.endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		return a, nil, errors.New("explicit CA requires an HTTPS control endpoint")
	}

	client, err := trust.NewHTTPClientFromCAFile(o.caFile)
	if err != nil {
		return a, nil, err
	}

	a.Client = client

	return a, client.CloseIdleConnections, nil
}

func keyID(cmd *cobra.Command, o *options) {
	cmd.Flags().StringVar(&o.keyID, "key-id", "root-1", "root key identifier")
}

// resolve applies only non-empty configured defaults to flags which were not
// explicitly changed. The selected passphrase file is read only by an action.
func resolve(cmd *cobra.Command, o *options) (platformconfig.Admin, error) {
	if err := cmd.Context().Err(); err != nil {
		return platformconfig.Admin{}, err
	}

	if strings.TrimSpace(o.config) == "" {
		return platformconfig.Admin{}, nil
	}

	cfg, err := platformconfig.LoadAdmin(o.config)
	if err != nil {
		return platformconfig.Admin{}, err
	}

	applyString(cmd, "key", &o.key, cfg.RootKeyFile)
	applyString(cmd, "passphrase-file", &o.passphraseFile, cfg.PassphraseFile)
	applyString(cmd, "endpoint", &o.endpoint, cfg.Endpoint)
	applyString(cmd, "ca-file", &o.caFile, cfg.CAFile)
	applyString(cmd, "key-id", &o.keyID, cfg.KeyID)
	applyString(cmd, "manifest", &o.manifest, cfg.SnapshotManifestFile)
	applyString(cmd, "network", &o.network, cfg.NetworkID)
	applyString(cmd, "profile", &o.profile, cfg.ProfileID)
	applyString(cmd, "base-url", &o.baseURL, cfg.BaseURL)
	applyString(cmd, "overlay-pool", &o.overlayPool, cfg.OverlayPool)
	return cfg, nil
}

func applyString(cmd *cobra.Command, name string, target *string, configured string) {
	flag := cmd.Flags().Lookup(name)
	if flag != nil && !flag.Changed && configured != "" {
		*target = configured
	}
}

func newInitRoot() *cobra.Command {
	o := new(options)
	cmd := &cobra.Command{
		Use:  "init-root",
		Args: host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := resolve(cmd, o); err != nil {
				return err
			}

			passphrase, err := readPassphrase(o.passphraseFile)
			if err != nil {
				return err
			}

			store, err := companion.NewRootKeyStore(o.key)
			if err != nil {
				return err
			}

			publicKey, err := store.Create(passphrase)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintln(
				cmd.OutOrStdout(),
				base64.RawURLEncoding.EncodeToString(publicKey),
			)

			return err
		},
	}
	common(cmd, o)
	return cmd
}

func newInitSnapshot() *cobra.Command {
	o := new(options)
	cmd := &cobra.Command{
		Use: "init-snapshot", Args: host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := resolve(cmd, o); err != nil {
				return err
			}

			if strings.TrimSpace(o.manifest) == "" {
				return errors.New("manifest is required")
			}

			manifest, err := companion.LoadSnapshotManifest(o.manifest)
			if err != nil {
				return err
			}

			session, err := unlockSession(o.key, o.passphraseFile)
			if err != nil {
				return err
			}

			root, err := session.PrivateKey()
			if err != nil {
				return err
			}

			envelope, err := manifest.SignInitialSnapshot(root, o.keyID)
			if err != nil {
				return err
			}

			approver, closeClient, err := remoteApprover(*o)
			if err != nil {
				return err
			}
			defer closeClient()

			if err := approver.PublishInitialSnapshot(
				cmd.Context(),
				envelope,
			); err != nil {
				return err
			}

			_, err = fmt.Fprintf(
				cmd.OutOrStdout(),
				"initial snapshot published: network=%s revision=1 hash=%s\n",
				manifest.NetworkID,
				base64.RawURLEncoding.EncodeToString(envelope.Hash),
			)

			return err
		},
	}
	common(cmd, o)
	remote(cmd, o)
	keyID(cmd, o)
	cmd.Flags().StringVar(&o.manifest, "manifest", "", "initial snapshot TOML manifest")
	return cmd
}

func newInvite() *cobra.Command {
	o := new(options)
	cmd := &cobra.Command{
		Use: "invite", Args: host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := resolve(cmd, o); err != nil {
				return err
			}

			session, err := unlockSession(o.key, o.passphraseFile)
			if err != nil {
				return err
			}

			issuer := companion.NewInviteIssuer(session, o.network, o.baseURL, o.keyID, time.Now)
			link, code, inviteID, err := issuer.Issue(o.profile, o.ttl)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(
				cmd.OutOrStdout(),
				"invite_id=%s\nlink=%s\ncode=%s\n",
				inviteID,
				link,
				code,
			)

			return err
		},
	}
	common(cmd, o)
	keyID(cmd, o)
	cmd.Flags().StringVar(&o.network, "network", "home", "network ID")
	cmd.Flags().StringVar(&o.profile, "profile", "family", "access profile ID")
	cmd.Flags().
		StringVar(&o.baseURL, "base-url", "https://control.example/invite", "invite landing URL")
	cmd.Flags().DurationVar(&o.ttl, "ttl", 10*time.Minute, "invite lifetime")
	return cmd
}

func newApprove() *cobra.Command {
	o := new(options)
	cmd := &cobra.Command{
		Use: "approve", Args: host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := resolve(cmd, o)
			if err != nil {
				return err
			}
			if strings.TrimSpace(o.invite) == "" {
				return errors.New("invite is required")
			}

			scanner := bufio.NewScanner(cmd.InOrStdin())
			scanner.Buffer(make([]byte, 4096), 16*1024)

			code, err := host.ReadPrivateLine(scanner, cmd, "Invitation code")
			if err != nil {
				return err
			}

			attempts, err := companion.NewFileInviteAttemptStore(cfg.InviteAttemptsFile)
			if err != nil {
				return err
			}

			session, err := unlockSession(o.key, o.passphraseFile)
			if err != nil {
				return err
			}

			root, err := session.PrivateKey()
			if err != nil {
				return err
			}

			approver, closeClient, err := remoteApprover(*o)
			if err != nil {
				return err
			}
			defer closeClient()

			approver.Attempts = attempts

			return approver.Approve(
				cmd.Context(),
				o.invite,
				code,
				root,
			)
		},
	}
	common(cmd, o)
	remote(cmd, o)
	cmd.Flags().StringVar(&o.invite, "invite", "", "pending invite ID")
	return cmd
}

func newPublishSnapshot() *cobra.Command {
	o := new(options)
	cmd := &cobra.Command{
		Use: "publish-snapshot", Args: host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := resolve(cmd, o); err != nil {
				return err
			}

			if o.invite == "" || o.overlayPool == "" {
				return errors.New("invite and overlay-pool are required")
			}

			pool, err := netip.ParsePrefix(o.overlayPool)
			if err != nil {
				return fmt.Errorf("parse overlay-pool: %w", err)
			}

			session, err := unlockSession(o.key, o.passphraseFile)
			if err != nil {
				return err
			}

			root, err := session.PrivateKey()
			if err != nil {
				return err
			}

			approver, closeClient, err := remoteApprover(*o)
			if err != nil {
				return err
			}
			defer closeClient()

			approver.OverlayPool = pool

			return approver.PublishSnapshot(
				cmd.Context(),
				strings.TrimSpace(o.invite),
				root,
			)
		},
	}
	common(cmd, o)
	remote(cmd, o)
	keyID(cmd, o)
	cmd.Flags().StringVar(&o.invite, "invite", "", "approved invite ID")
	cmd.Flags().
		StringVar(&o.overlayPool, "overlay-pool", "", "IPv4 RFC1918/CGNAT overlay pool, for example 10.200.0.0/24")
	return cmd
}

func newRevokeDevice() *cobra.Command {
	o := new(options)
	cmd := &cobra.Command{
		Use: "revoke-device", Args: host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := resolve(cmd, o); err != nil {
				return err
			}

			if strings.TrimSpace(o.device) == "" {
				return errors.New("device is required")
			}

			session, err := unlockSession(o.key, o.passphraseFile)
			if err != nil {
				return err
			}

			root, err := session.PrivateKey()
			if err != nil {
				return err
			}

			approver, closeClient, err := remoteApprover(*o)
			if err != nil {
				return err
			}
			defer closeClient()

			return approver.PublishDeviceRemoval(
				cmd.Context(),
				strings.TrimSpace(o.device),
				root,
			)
		},
	}
	common(cmd, o)
	remote(cmd, o)
	keyID(cmd, o)
	cmd.Flags().
		StringVar(&o.device, "device", "", "client device ID to remove from the signed network snapshot")
	return cmd
}

func unlockSession(path, passphraseFile string) (*companion.Session, error) {
	passphrase, err := readPassphrase(passphraseFile)
	if err != nil {
		return nil, err
	}

	store, err := companion.NewRootKeyStore(path)
	if err != nil {
		return nil, err
	}

	privateKey, err := store.Unlock(passphrase)
	if err != nil {
		return nil, err
	}

	session := companion.NewSession(time.Now)

	return session, session.Unlock(privateKey)
}

func readPassphrase(path string) (string, error) {
	if path == "" {
		return "", errors.New(
			"passphrase-file is required; do not pass secrets as command-line arguments",
		)
	}

	value, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	secret := strings.TrimSpace(string(value))
	if secret == "" {
		return "", errors.New("passphrase file is empty")
	}

	return secret, nil
}
