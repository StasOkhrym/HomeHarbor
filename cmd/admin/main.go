// Command admin is the local trusted companion preview. It deliberately talks
// to the control plane only with signed permits/proofs; root private keys and
// invite codes remain on the Mac.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/sokhrym/go-tunnels/internal/companion"
	platformconfig "github.com/sokhrym/go-tunnels/internal/platform/config"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init-root":
		err = initRoot(os.Args[2:])
	case "invite":
		err = issueInvite(os.Args[2:])
	case "approve":
		err = approveInvite(os.Args[2:])
	case "publish-snapshot":
		err = publishInviteSnapshot(os.Args[2:])
	case "init-snapshot":
		err = initSnapshot(os.Args[2:])
	case "revoke-device":
		err = revokeDeviceSnapshot(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initSnapshot(args []string) error {
	flags := flag.NewFlagSet("init-snapshot", flag.ContinueOnError)
	configPath := flags.String("config", "", "admin TOML configuration path")
	manifestPath := flags.String("manifest", "", "initial snapshot TOML manifest")
	keyPath := flags.String("key", "state/root-key.age", "encrypted root key path")
	passphraseFile := flags.String("passphrase-file", "", "file containing the passphrase")
	endpoint := flags.String("endpoint", "https://control.example", "control plane URL")
	keyID := flags.String("key-id", "root-1", "root key identifier")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadAdminConfig(*configPath)
	if err != nil {
		return err
	}
	applyAdminString(flags, "manifest", manifestPath, cfg.SnapshotManifestFile)
	applyAdminString(flags, "key", keyPath, cfg.RootKeyFile)
	applyAdminString(flags, "passphrase-file", passphraseFile, cfg.PassphraseFile)
	applyAdminString(flags, "endpoint", endpoint, cfg.Endpoint)
	applyAdminString(flags, "key-id", keyID, cfg.KeyID)
	if strings.TrimSpace(*manifestPath) == "" {
		return errors.New("manifest is required")
	}
	manifest, err := companion.LoadSnapshotManifest(*manifestPath)
	if err != nil {
		return err
	}
	session, err := unlockSessionWithPassphrase(*keyPath, *passphraseFile, cfg.Passphrase)
	if err != nil {
		return err
	}
	root, err := session.PrivateKey()
	if err != nil {
		return err
	}
	envelope, err := manifest.SignInitialSnapshot(root, *keyID)
	if err != nil {
		return err
	}
	if err := (companion.RemoteApprover{Endpoint: *endpoint}).PublishInitialSnapshot(
		context.Background(),
		envelope,
	); err != nil {
		return err
	}
	fmt.Printf(
		"initial snapshot published: network=%s revision=1 hash=%s\n",
		manifest.NetworkID,
		base64.RawURLEncoding.EncodeToString(envelope.Hash),
	)
	return nil
}

func initRoot(args []string) error {
	flags := flag.NewFlagSet("init-root", flag.ContinueOnError)
	configPath := flags.String("config", "", "admin TOML configuration path")
	path := flags.String("key", "state/root-key.age", "encrypted root key path")
	passphraseFile := flags.String("passphrase-file", "", "file containing the passphrase")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadAdminConfig(*configPath)
	if err != nil {
		return err
	}
	applyAdminString(flags, "key", path, cfg.RootKeyFile)
	applyAdminString(flags, "passphrase-file", passphraseFile, cfg.PassphraseFile)
	passphrase, err := configuredPassphrase(*passphraseFile, cfg.Passphrase)
	if err != nil {
		return err
	}
	store, err := companion.NewRootKeyStore(*path)
	if err != nil {
		return err
	}
	publicKey, err := store.Create(passphrase)
	if err != nil {
		return err
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(publicKey))
	return nil
}

func issueInvite(args []string) error {
	flags := flag.NewFlagSet("invite", flag.ContinueOnError)
	configPath := flags.String("config", "", "admin TOML configuration path")
	keyPath := flags.String("key", "state/root-key.age", "encrypted root key path")
	passphraseFile := flags.String("passphrase-file", "", "file containing the passphrase")
	networkID := flags.String("network", "home", "network ID")
	profileID := flags.String("profile", "family", "access profile ID")
	baseURL := flags.String("base-url", "https://control.example/invite", "invite landing URL")
	keyID := flags.String("key-id", "root-1", "root key identifier")
	ttl := flags.Duration("ttl", 10*time.Minute, "invite lifetime")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadAdminConfig(*configPath)
	if err != nil {
		return err
	}
	applyAdminString(flags, "key", keyPath, cfg.RootKeyFile)
	applyAdminString(flags, "passphrase-file", passphraseFile, cfg.PassphraseFile)
	applyAdminString(flags, "network", networkID, cfg.NetworkID)
	applyAdminString(flags, "profile", profileID, cfg.ProfileID)
	applyAdminString(flags, "base-url", baseURL, cfg.BaseURL)
	applyAdminString(flags, "key-id", keyID, cfg.KeyID)
	session, err := unlockSessionWithPassphrase(*keyPath, *passphraseFile, cfg.Passphrase)
	if err != nil {
		return err
	}
	issuer := companion.NewInviteIssuer(session, *networkID, *baseURL, *keyID, time.Now)
	link, code, inviteID, err := issuer.Issue(*profileID, *ttl)
	if err != nil {
		return err
	}
	fmt.Printf("invite_id=%s\nlink=%s\ncode=%s\n", inviteID, link, code)
	return nil
}

func approveInvite(args []string) error {
	flags := flag.NewFlagSet("approve", flag.ContinueOnError)
	configPath := flags.String("config", "", "admin TOML configuration path")
	keyPath := flags.String("key", "state/root-key.age", "encrypted root key path")
	passphraseFile := flags.String("passphrase-file", "", "file containing the passphrase")
	endpoint := flags.String("endpoint", "https://control.example", "control plane URL")
	inviteID := flags.String("invite", "", "pending invite ID")
	code := flags.String("code", "", "short code received separately")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadAdminConfig(*configPath)
	if err != nil {
		return err
	}
	applyAdminString(flags, "key", keyPath, cfg.RootKeyFile)
	applyAdminString(flags, "passphrase-file", passphraseFile, cfg.PassphraseFile)
	applyAdminString(flags, "endpoint", endpoint, cfg.Endpoint)
	if *inviteID == "" || *code == "" {
		return errors.New("invite and code are required")
	}
	attempts, err := companion.NewFileInviteAttemptStore(cfg.InviteAttemptsFile)
	if err != nil {
		return err
	}
	session, err := unlockSessionWithPassphrase(*keyPath, *passphraseFile, cfg.Passphrase)
	if err != nil {
		return err
	}
	root, err := session.PrivateKey()
	if err != nil {
		return err
	}
	return (companion.RemoteApprover{Endpoint: *endpoint, Attempts: attempts}).Approve(
		context.Background(),
		*inviteID,
		strings.TrimSpace(*code),
		root,
	)
}

func publishInviteSnapshot(args []string) error {
	flags := flag.NewFlagSet("publish-snapshot", flag.ContinueOnError)
	configPath := flags.String("config", "", "admin TOML configuration path")
	keyPath := flags.String("key", "state/root-key.age", "encrypted root key path")
	passphraseFile := flags.String("passphrase-file", "", "file containing the passphrase")
	endpoint := flags.String("endpoint", "https://control.example", "control plane URL")
	keyID := flags.String("key-id", "root-1", "root key identifier")
	inviteID := flags.String("invite", "", "approved invite ID")
	overlayPool := flags.String("overlay-pool", "", "IPv4 RFC1918/CGNAT overlay pool, for example 10.200.0.0/24")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadAdminConfig(*configPath)
	if err != nil {
		return err
	}
	applyAdminString(flags, "key", keyPath, cfg.RootKeyFile)
	applyAdminString(flags, "passphrase-file", passphraseFile, cfg.PassphraseFile)
	applyAdminString(flags, "endpoint", endpoint, cfg.Endpoint)
	applyAdminString(flags, "key-id", keyID, cfg.KeyID)
	applyAdminString(flags, "overlay-pool", overlayPool, cfg.OverlayPool)
	if *inviteID == "" || *overlayPool == "" {
		return errors.New("invite and overlay-pool are required")
	}
	pool, err := netip.ParsePrefix(*overlayPool)
	if err != nil {
		return fmt.Errorf("parse overlay-pool: %w", err)
	}
	session, err := unlockSessionWithPassphrase(*keyPath, *passphraseFile, cfg.Passphrase)
	if err != nil {
		return err
	}
	root, err := session.PrivateKey()
	if err != nil {
		return err
	}
	return (companion.RemoteApprover{Endpoint: *endpoint, KeyID: *keyID, OverlayPool: pool}).PublishSnapshot(
		context.Background(),
		strings.TrimSpace(*inviteID),
		root,
	)
}

func revokeDeviceSnapshot(args []string) error {
	flags := flag.NewFlagSet("revoke-device", flag.ContinueOnError)
	configPath := flags.String("config", "", "admin TOML configuration path")
	keyPath := flags.String("key", "state/root-key.age", "encrypted root key path")
	passphraseFile := flags.String("passphrase-file", "", "file containing the passphrase")
	endpoint := flags.String("endpoint", "https://control.example", "control plane URL")
	keyID := flags.String("key-id", "root-1", "root key identifier")
	deviceID := flags.String("device", "", "client device ID to remove from the signed network snapshot")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadAdminConfig(*configPath)
	if err != nil {
		return err
	}
	applyAdminString(flags, "key", keyPath, cfg.RootKeyFile)
	applyAdminString(flags, "passphrase-file", passphraseFile, cfg.PassphraseFile)
	applyAdminString(flags, "endpoint", endpoint, cfg.Endpoint)
	applyAdminString(flags, "key-id", keyID, cfg.KeyID)
	if strings.TrimSpace(*deviceID) == "" {
		return errors.New("device is required")
	}
	session, err := unlockSessionWithPassphrase(*keyPath, *passphraseFile, cfg.Passphrase)
	if err != nil {
		return err
	}
	root, err := session.PrivateKey()
	if err != nil {
		return err
	}
	return (companion.RemoteApprover{Endpoint: *endpoint, KeyID: *keyID}).PublishDeviceRemoval(
		context.Background(),
		strings.TrimSpace(*deviceID),
		root,
	)
}

func loadAdminConfig(path string) (platformconfig.Admin, error) {
	if strings.TrimSpace(path) == "" {
		return platformconfig.Admin{}, nil
	}
	return platformconfig.LoadAdmin(path)
}

func applyAdminString(flags *flag.FlagSet, name string, target *string, configured string) {
	if configured != "" && !flagWasProvided(flags, name) {
		*target = configured
	}
}

func flagWasProvided(flags *flag.FlagSet, name string) bool {
	provided := false
	flags.Visit(func(item *flag.Flag) {
		if item.Name == name {
			provided = true
		}
	})
	return provided
}

func configuredPassphrase(passphraseFile, configured string) (string, error) {
	if passphraseFile != "" {
		return readPassphrase(passphraseFile)
	}
	if configured != "" {
		return configured, nil
	}
	return "", errors.New("passphrase-file is required; do not pass secrets as command-line arguments")
}

func unlockSessionWithPassphrase(path, passphraseFile, configuredSecret string) (*companion.Session, error) {
	passphrase, err := configuredPassphrase(passphraseFile, configuredSecret)
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
		return "", errors.New("passphrase-file is required; do not pass secrets as command-line arguments")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value = []byte(strings.TrimSpace(string(value)))
	if len(value) == 0 {
		return "", errors.New("passphrase file is empty")
	}
	return string(value), nil
}

func usage() {
	fmt.Fprintln(
		os.Stderr,
		"usage: admin init-root|init-snapshot|invite|approve|publish-snapshot|revoke-device [flags]",
	)
}
