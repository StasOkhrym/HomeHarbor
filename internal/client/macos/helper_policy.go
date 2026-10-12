package macos

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
)

const maxHelperPolicyBytes = 8 * 1024

// HelperPolicyDocument is installed explicitly by an administrator in a
// root-owned private file. It contains only public trust and bounded network
// scope; the companion signing key never enters this process.
type HelperPolicyDocument struct {
	Version       int    `json:"version"`
	OwnerUID      int    `json:"owner_uid"`
	RootPublicKey string `json:"root_public_key"`
	NetworkID     string `json:"network_id"`
	DeviceID      string `json:"device_id"`
	Overlay       string `json:"overlay"`
	Private       string `json:"private"`
	Suffix        string `json:"suffix"`
}

// LoadHelperPolicy uses localstate's no-follow, owner/mode-checked open path.
// The system entrypoint supplies fixed paths, never paths from helper stdin.
func LoadHelperPolicy(path, journalPath string) (policy HelperPolicy, result error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(journalPath) {
		return HelperPolicy{}, errors.New("native helper paths must be absolute")
	}
	store, err := localstate.Open(path)
	if err != nil {
		return HelperPolicy{}, fmt.Errorf("open native helper policy: %w", err)
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	data, err := store.Read()
	if err != nil {
		return HelperPolicy{}, fmt.Errorf("read native helper policy: %w", err)
	}
	if len(data) > maxHelperPolicyBytes {
		return HelperPolicy{}, errors.New("native helper policy exceeds size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document HelperPolicyDocument
	if err := decoder.Decode(&document); err != nil {
		return HelperPolicy{}, fmt.Errorf("decode native helper policy: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return HelperPolicy{}, errors.New("native helper policy contains trailing data")
	}
	root, err := base64.RawURLEncoding.Strict().DecodeString(document.RootPublicKey)
	if err != nil || len(root) != ed25519.PublicKeySize {
		return HelperPolicy{}, errors.New("native helper policy has invalid root public key")
	}
	overlay, overlayErr := netip.ParsePrefix(document.Overlay)
	private, privateErr := netip.ParsePrefix(document.Private)
	if document.Version != 1 || document.OwnerUID <= 0 || document.NetworkID == "" ||
		document.DeviceID == "" || overlayErr != nil || privateErr != nil ||
		!overlay.IsValid() || !private.IsValid() || overlay.Bits() == 0 ||
		private.Bits() == 0 || overlay != overlay.Masked() ||
		private != private.Masked() || overlay.Overlaps(private) ||
		!withinPrivateScope(overlay, true) || !withinPrivateScope(private, false) ||
		!validResolverSuffix(document.Suffix) {
		return HelperPolicy{}, errors.New("native helper policy has invalid trust bounds")
	}
	return HelperPolicy{
		Authority: Authority{
			Root: ed25519.PublicKey(root), NetworkID: document.NetworkID,
			DeviceID: document.DeviceID,
			Bounds: networkplan.Bounds{
				Overlay: overlay, Private: private, Suffix: document.Suffix,
			},
		},
		OwnerUID: document.OwnerUID, JournalPath: journalPath,
	}, nil
}

func withinPrivateScope(prefix netip.Prefix, overlay bool) bool {
	if !prefix.Addr().Is4() || prefix.Bits() < 16 {
		return false
	}

	allowed := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	if overlay {
		allowed = append(allowed, netip.MustParsePrefix("100.64.0.0/10"))
	}

	for _, scope := range allowed {
		if prefix.Bits() >= scope.Bits() && scope.Contains(prefix.Addr()) {
			return true
		}
	}

	return false
}

func validResolverSuffix(suffix string) bool {
	if len(suffix) == 0 || len(suffix) > 253 || suffix != strings.ToLower(suffix) {
		return false
	}

	for label := range strings.SplitSeq(suffix, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, char := range label {
			if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
				continue
			}

			return false
		}
	}

	return true
}
