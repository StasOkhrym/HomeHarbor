package macos

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// HelperExecutor owns the private local subprocess protocol. Coordination
// crosses this seam only after compilation of an independently verified plan.
type HelperExecutor interface {
	Execute(context.Context, HelperRequest) error
}

// Controller consumes signed coordination without elevated privileges. It
// serializes apply/close and remembers failed requests that may have partially
// changed the host; the root helper retains durable revision and ownership.
type Controller struct {
	mu         sync.Mutex
	authority  Authority
	privateKey string
	timeout    time.Duration
	helper     HelperExecutor
	touched    bool
}

func NewController(
	authority Authority,
	privateKey string,
	timeout time.Duration,
	helper HelperExecutor,
) (*Controller, error) {
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil || key == (wgtypes.Key{}) || len(authority.Root) != ed25519.PublicKeySize ||
		authority.NetworkID == "" || authority.DeviceID == "" || !validNativeBounds(authority.Bounds) ||
		timeout <= 0 || helper == nil {
		return nil, errors.New(
			"native controller requires identity, trust bounds and a bounded helper",
		)
	}

	authority.Root = append(ed25519.PublicKey(nil), authority.Root...)

	// The root journal can outlive this ordinary process. Startup closes that
	// ownership before a relay worker can reactivate a previous packet plane.
	return &Controller{
		authority:  authority,
		privateKey: privateKey,
		timeout:    timeout,
		helper:     helper,
		touched:    true,
	}, nil
}

func (*Controller) Apply(context.Context, snapshot.NetworkSnapshot) error {
	return errors.New("native controller requires the original signed envelope")
}

// VerifyRestore authenticates the checkpoint without reopening old host
// policy. Coordination applies the current head after admitted TLS startup.
func (c *Controller) VerifyRestore(
	ctx context.Context,
	envelope snapshot.Envelope,
	_ snapshot.NetworkSnapshot,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Historic scope may differ after an explicit configuration change. The
	// checkpoint anchors lineage; current bounds are enforced only at apply.
	_, err := snapshot.Verify(envelope, c.authority.Root, c.authority.NetworkID)

	return err
}

func (c *Controller) ApplySigned(
	ctx context.Context,
	envelope snapshot.Envelope,
	_ snapshot.NetworkSnapshot,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	plan, err := networkplan.CompileSigned(
		envelope,
		c.authority.Root,
		c.authority.NetworkID,
		c.authority.DeviceID,
		c.authority.Bounds,
	)
	if err != nil {
		return err
	}

	request := HelperRequest{Version: 1, Action: "apply", Envelope: envelope, Plan: plan}
	if !plan.Revoked {
		request.PrivateKey = c.privateKey
	}

	operation, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// A lost response cannot prove that the helper made no host changes.
	c.touched = true

	if err := c.helper.Execute(operation, request); err != nil {
		return fmt.Errorf("apply native signed network: %w", err)
	}

	return nil
}

func (c *Controller) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.touched {
		return nil
	}

	if err := CloseOwned(ctx, c.authority, c.timeout, c.helper); err != nil {
		return err
	}

	c.touched = false

	return nil
}

// CloseOwned requests scoped journal cleanup without private keys or control
// connectivity. The installed policy independently validates the public owner.
func CloseOwned(
	ctx context.Context,
	authority Authority,
	timeout time.Duration,
	helper HelperExecutor,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if len(authority.Root) != ed25519.PublicKeySize || authority.NetworkID == "" ||
		authority.DeviceID == "" || timeout <= 0 || helper == nil {
		return errors.New("native cleanup requires public ownership and a bounded helper")
	}

	operation, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := helper.Execute(
		operation,
		HelperRequest{Version: 1, Action: "close", Owner: helperOwner(authority)},
	); err != nil {
		return fmt.Errorf("close native owned network: %w", err)
	}

	return nil
}
