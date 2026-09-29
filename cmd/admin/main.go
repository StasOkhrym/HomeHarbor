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
	"os"
	"strings"
	"time"

	"github.com/sokhrym/go-tunnels/internal/companion"
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
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initRoot(args []string) error {
	flags := flag.NewFlagSet("init-root", flag.ContinueOnError)
	path := flags.String("key", "state/root-key.age", "encrypted root key path")
	passphraseFile := flags.String("passphrase-file", "", "file containing the passphrase")
	if err := flags.Parse(args); err != nil {
		return err
	}
	passphrase, err := readPassphrase(*passphraseFile)
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
	session, err := unlockSession(*keyPath, *passphraseFile)
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
	keyPath := flags.String("key", "state/root-key.age", "encrypted root key path")
	passphraseFile := flags.String("passphrase-file", "", "file containing the passphrase")
	endpoint := flags.String("endpoint", "https://control.example", "control plane URL")
	inviteID := flags.String("invite", "", "pending invite ID")
	code := flags.String("code", "", "short code received separately")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *inviteID == "" || *code == "" {
		return errors.New("invite and code are required")
	}
	session, err := unlockSession(*keyPath, *passphraseFile)
	if err != nil {
		return err
	}
	root, err := session.PrivateKey()
	if err != nil {
		return err
	}
	return (companion.RemoteApprover{Endpoint: *endpoint}).Approve(context.Background(), *inviteID, strings.TrimSpace(*code), root)
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
	fmt.Fprintln(os.Stderr, "usage: admin init-root|invite|approve [flags]")
}
