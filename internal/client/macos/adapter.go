// Package macos owns the opt-in native sandbox network transaction. The
// signed snapshot and independently provisioned bounds are checked again at
// this privileged boundary; a caller-provided plan is never sole authority.
package macos

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

var ErrOwnershipConflict = errors.New("native resource changed outside HomeHarbor ownership")

var utunName = regexp.MustCompile(`^utun[0-9]{1,4}$`)

type Authority struct {
	Root      ed25519.PublicKey
	NetworkID string
	DeviceID  string
	Bounds    networkplan.Bounds
}

// TunnelConfig combines caller-held identity with the root-provisioned local
// UDP bridge and listen port. Only the identity travels through helper stdin.
type TunnelConfig struct {
	PrivateKey     string
	BridgeEndpoint netip.AddrPort
	ListenPort     uint16
}

// Operations is the small native effect boundary. Each Remove method must
// inspect the current resource and refuse foreign changes, not blindly delete.
type Operations interface {
	Prepare(context.Context, networkplan.Plan) error
	Create(context.Context, string) (string, error)
	ResolveCreated(context.Context, string) (string, error)
	Configure(context.Context, string, networkplan.Plan, TunnelConfig) error
	Address(context.Context, string, netip.Prefix) error
	AddRoute(context.Context, string, netip.Prefix) error
	SetDNS(context.Context, networkplan.Resolver) error
	RemoveDNS(context.Context, networkplan.Resolver) error
	RemoveRoute(context.Context, string, netip.Prefix) error
	CloseTunnel(context.Context, string) error
}

type Adapter struct {
	journalPath string
	authority   Authority
	envelope    snapshot.Envelope
	ops         Operations
	tunnel      TunnelConfig
}

func NewAdapter(
	journalPath string,
	authority Authority,
	envelope snapshot.Envelope,
	ops Operations,
	tunnel TunnelConfig,
) *Adapter {
	return &Adapter{
		journalPath: journalPath, authority: authority, envelope: envelope,
		ops: ops, tunnel: tunnel,
	}
}

// Apply validates the exact signed plan, recovers stale intent, then journals
// every resource before its mutation. A failed stage never advances the
// applied revision, and recovery uses a fresh bounded context on cancellation.
func (a *Adapter) Apply(ctx context.Context, plan networkplan.Plan) (result error) {
	if a == nil || a.ops == nil {
		return errors.New("native adapter is not configured")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	expected, err := networkplan.CompileSigned(
		a.envelope, a.authority.Root, a.authority.NetworkID,
		a.authority.DeviceID, a.authority.Bounds,
	)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, plan) {
		return errors.New("native plan differs from the verified signed snapshot")
	}

	store, err := localstate.Open(a.journalPath)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()

	state, err := loadJournal(store, a.authority)
	if err != nil {
		return err
	}
	if plan.Revision < state.HighestRevision ||
		plan.Revision == state.HighestRevision &&
			state.HighestHash != "" && state.HighestHash != plan.EnvelopeHash {
		return errors.New("native signed revision rollback or equivocation")
	}

	// Remember new signed authority before touching the host. A failed apply
	// must never permit an older signed policy to reopen access afterward.
	state.HighestRevision, state.HighestHash = plan.Revision, plan.EnvelopeHash

	if err := saveJournal(store, state); err != nil {
		return err
	}

	if err := a.cleanup(ctx, store, &state); err != nil {
		return fmt.Errorf("recover previous native ownership: %w", err)
	}

	if plan.Revoked {
		return nil
	}

	if err := a.ops.Prepare(ctx, plan); err != nil {
		return err
	}

	state.Phase = "prepared"

	if err := saveJournal(store, state); err != nil {
		return err
	}

	applyErr := a.install(ctx, store, &state, plan)
	if applyErr != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return errors.Join(applyErr, a.cleanup(cleanup, store, &state))
	}

	state.AppliedRevision, state.Phase = plan.Revision, "applied"

	if err := saveJournal(store, state); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return errors.Join(err, a.cleanup(cleanup, store, &state))
	}

	return nil
}

func (a *Adapter) install(
	ctx context.Context,
	store *localstate.Store,
	state *journalState,
	plan networkplan.Plan,
) error {
	name, err := a.ops.Create(ctx, a.journalPath)
	if err != nil {
		return fmt.Errorf("create native tunnel: %w", err)
	}
	if !utunName.MatchString(name) {
		return errors.New("native tunnel returned an invalid interface name")
	}

	state.Interface = name

	if err := saveJournal(store, *state); err != nil {
		return err
	}

	if err := a.ops.Configure(ctx, name, plan, a.tunnel); err != nil {
		return fmt.Errorf("configure native WireGuard: %w", err)
	}

	if err := a.ops.Address(ctx, name, plan.OverlayAddress); err != nil {
		return fmt.Errorf("assign native overlay address: %w", err)
	}

	for _, route := range plan.Routes {
		state.Routes = append(state.Routes, route)

		if err := saveJournal(store, *state); err != nil {
			return err
		}

		if err := a.ops.AddRoute(ctx, name, route); err != nil {
			return fmt.Errorf("install native route %s: %w", route, err)
		}
	}

	for _, resolver := range plan.DNS {
		state.DNS = append(state.DNS, resolver)

		if err := saveJournal(store, *state); err != nil {
			return err
		}

		if err := a.ops.SetDNS(ctx, resolver); err != nil {
			return fmt.Errorf("install scoped native resolver: %w", err)
		}
	}

	return nil
}

// Close removes only journaled resources in reverse order and retains every
// conflicting entry for a later explicit recovery attempt.
func (a *Adapter) Close(ctx context.Context) (result error) {
	if a == nil || a.ops == nil {
		return errors.New("native adapter is not configured")
	}

	store, err := localstate.Open(a.journalPath)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()

	state, err := loadJournal(store, a.authority)
	if err != nil {
		return err
	}

	return a.cleanup(ctx, store, &state)
}

func (a *Adapter) cleanup(
	ctx context.Context,
	store *localstate.Store,
	state *journalState,
) error {
	if state.Phase == "" && state.Interface == "" && len(state.Routes) == 0 && len(state.DNS) == 0 {
		return nil
	}

	state.AppliedRevision = 0
	state.Phase = "cleanup"

	if err := saveJournal(store, *state); err != nil {
		return err
	}

	var all error
	for index := len(state.DNS) - 1; index >= 0; index-- {
		resolver := state.DNS[index]
		if err := a.ops.RemoveDNS(ctx, resolver); err != nil {
			all = errors.Join(all, err)
			continue
		}

		state.DNS = slices.Delete(state.DNS, index, index+1)

		if err := saveJournal(store, *state); err != nil {
			return errors.Join(all, err)
		}
	}

	if state.Interface == "" {
		name, err := a.ops.ResolveCreated(ctx, a.journalPath)
		if err != nil {
			all = errors.Join(all, err)
		} else if name != "" && !utunName.MatchString(name) {
			all = errors.Join(all, errors.New("recovered native interface name is invalid"))
		} else if name != "" {
			state.Interface = name

			if err := saveJournal(store, *state); err != nil {
				return errors.Join(all, err)
			}
		}
	}

	for index := len(state.Routes) - 1; index >= 0; index-- {
		if state.Interface == "" {
			all = errors.Join(
				all,
				errors.New("native interface name unavailable for route recovery"),
			)
			break
		}

		route := state.Routes[index]
		if err := a.ops.RemoveRoute(ctx, state.Interface, route); err != nil {
			all = errors.Join(all, err)
			continue
		}

		state.Routes = slices.Delete(state.Routes, index, index+1)

		if err := saveJournal(store, *state); err != nil {
			return errors.Join(all, err)
		}
	}

	if len(state.DNS) == 0 && len(state.Routes) == 0 && state.Interface != "" {
		if err := a.ops.CloseTunnel(ctx, state.Interface); err != nil {
			all = errors.Join(all, err)
		} else {
			state.Interface = ""

			if err := saveJournal(store, *state); err != nil {
				return errors.Join(all, err)
			}
		}
	}

	if all == nil && len(state.DNS) == 0 && len(state.Routes) == 0 && state.Interface == "" {
		state.Phase = ""
		return saveJournal(store, *state)
	}

	return all
}
