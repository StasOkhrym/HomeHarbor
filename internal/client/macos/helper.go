package macos

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"

	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

const MaxHelperRequestBytes = 256 * 1024

// HelperPolicy comes from root-owned provisioned state, never from the caller's
// JSON. The caller may request an exact signed apply or cleanup of its owner.
type HelperPolicy struct {
	Authority   Authority
	OwnerUID    int
	JournalPath string
}

type HelperRequest struct {
	Version  int               `json:"version"`
	Action   string            `json:"action"`
	Envelope snapshot.Envelope `json:"envelope,omitempty"`
	Plan     networkplan.Plan  `json:"plan,omitempty"`
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
		!filepath.IsAbs(policy.JournalPath) || input == nil || ops == nil {
		return errors.New("native helper has invalid or foreign provisioned ownership")
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
	adapter := NewAdapter(policy.JournalPath, policy.Authority, request.Envelope, ops)
	switch request.Action {
	case "apply":
		return adapter.Apply(ctx, request.Plan)
	case "close":
		if !reflect.DeepEqual(request.Envelope, snapshot.Envelope{}) ||
			!reflect.DeepEqual(request.Plan, networkplan.Plan{}) {
			return errors.New("native close cannot carry a signed plan")
		}
		return adapter.Close(ctx)
	default:
		return errors.New("unknown native helper action")
	}
}
