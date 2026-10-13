package macos

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

const MaxHelperRequestBytes = 256 * 1024

// HelperPolicy comes from root-owned provisioned state, never from the caller's
// JSON. The caller may request an exact signed apply or cleanup of its owner.
type HelperPolicy struct {
	Authority               Authority
	OwnerUID                int
	JournalPath             string
	LocalWireGuardPublicKey string
	RelayPeerPublicKey      string
	Tunnel                  TunnelConfig
}

type HelperRequest struct {
	Version    int               `json:"version"`
	Action     string            `json:"action"`
	Owner      *HelperOwner      `json:"owner,omitempty"`
	Envelope   snapshot.Envelope `json:"envelope,omitempty"`
	Plan       networkplan.Plan  `json:"plan,omitempty"`
	PrivateKey string            `json:"private_key,omitempty"`
}

// HelperOwner binds journal-only cleanup to the caller's configured public
// trust. It carries no desired host state or private identity material.
type HelperOwner struct {
	NetworkID     string `json:"network_id"`
	DeviceID      string `json:"device_id"`
	RootPublicKey string `json:"root_public_key"`
}

func helperOwner(authority Authority) *HelperOwner {
	return &HelperOwner{
		NetworkID: authority.NetworkID, DeviceID: authority.DeviceID,
		RootPublicKey: base64.RawURLEncoding.EncodeToString(authority.Root),
	}
}

// ExecuteHelper validates the complete bounded protocol before any native
// effect. Apply re-verifies the signature and compares a compiled plan inside
// Adapter; close can only remove already journaled resources for this owner.
func ExecuteHelper(
	ctx context.Context,
	input io.Reader,
	policy HelperPolicy,
	callerUID int,
	ops Operations,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if policy.OwnerUID < 0 || callerUID != policy.OwnerUID ||
		len(policy.Authority.Root) != ed25519.PublicKeySize ||
		policy.Authority.NetworkID == "" || policy.Authority.DeviceID == "" ||
		!filepath.IsAbs(policy.JournalPath) || !validTunnelScope(policy.Tunnel) ||
		input == nil || ops == nil {
		return errors.New("native helper has invalid or foreign provisioned ownership")
	}

	pinnedKey, err := wgtypes.ParseKey(policy.LocalWireGuardPublicKey)
	if err != nil || pinnedKey == (wgtypes.Key{}) ||
		pinnedKey.String() != policy.LocalWireGuardPublicKey {
		return errors.New("native helper has invalid provisioned WireGuard identity")
	}

	data, err := io.ReadAll(io.LimitReader(input, MaxHelperRequestBytes+1))
	if err != nil {
		return fmt.Errorf("read native helper request: %w", err)
	}
	if len(data) > MaxHelperRequestBytes {
		return errors.New("native helper request exceeds its size bound")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request HelperRequest

	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode native helper request: %w", err)
	}

	var trailing any

	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("native helper request contains trailing data")
	}

	if request.Version != 1 {
		return errors.New("unsupported native helper request version")
	}

	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return errors.New("native helper request is not canonical JSON")
	}

	tunnel := policy.Tunnel
	tunnel.PrivateKey = request.PrivateKey
	adapter := NewAdapter(
		policy.JournalPath,
		policy.Authority,
		request.Envelope,
		ops,
		tunnel,
	)
	switch request.Action {
	case "apply":
		if request.Owner != nil {
			return errors.New("native apply ownership must derive from signed state")
		}

		if err := verifyNativePrivateKey(request, policy.Authority, pinnedKey); err != nil {
			return err
		}

		return adapter.Apply(ctx, request.Plan)
	case "close":
		if request.Owner == nil || *request.Owner != *helperOwner(policy.Authority) {
			return errors.New("native close ownership differs from installed policy")
		}
		if !reflect.DeepEqual(request.Envelope, snapshot.Envelope{}) ||
			!reflect.DeepEqual(request.Plan, networkplan.Plan{}) || request.PrivateKey != "" {
			return errors.New("native close cannot carry a signed plan")
		}

		return adapter.Close(ctx)
	default:
		return errors.New("unknown native helper action")
	}
}

func verifyNativePrivateKey(request HelperRequest, authority Authority, pinned wgtypes.Key) error {
	if request.Plan.Revoked {
		if request.PrivateKey != "" {
			return errors.New("revoked native plan cannot carry a private key")
		}

		return nil
	}

	key, err := wgtypes.ParseKey(request.PrivateKey)
	if err != nil {
		return errors.New("native WireGuard private key is invalid")
	}
	if key.PublicKey() != pinned {
		return errors.New("native WireGuard private key differs from provisioned client")
	}

	value, err := snapshot.Verify(request.Envelope, authority.Root, authority.NetworkID)
	if err != nil {
		return err
	}

	for _, device := range value.Devices {
		if device.ID == authority.DeviceID && device.Role == "client" &&
			device.WireGuardPublicKey == key.PublicKey().String() {
			return nil
		}
	}

	return errors.New("native WireGuard private key does not match the signed client")
}
