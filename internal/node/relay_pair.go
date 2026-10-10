package node

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/relay"
)

func newUDPPairBridge(cfg RelayBridgeConfig) (*relay.UDPPairBridge, error) {
	listen, err := net.ResolveUDPAddr("udp", cfg.ListenAddress)
	if err != nil {
		return nil, err
	}
	wg, err := net.ResolveUDPAddr("udp", cfg.WireGuardAddress)
	if err != nil {
		return nil, err
	}
	return relay.NewUDPPairBridge(
		relay.UDPPairBridgeConfig{
			ControlURL:          cfg.RelayURL,
			Ticket:              cfg.Ticket,
			SessionID:           cfg.SessionID,
			DeviceID:            cfg.DeviceID,
			DestinationDeviceID: cfg.DestinationDeviceID,
			ListenAddress:       listen,
			WireGuardAddress:    wg,
			HTTPClient:          cfg.RelayHTTPClient,
			OnObservedEndpoint:  cfg.OnObservedEndpoint,
		},
	)
}

// runUDPPairOwner retains the local endpoint through admission retries and
// renewal outages. It owns the renewal worker and awaits it before returning.
// A credential's lifetime schedules authentication; it never bounds Run.
func runUDPPairOwner(
	ctx context.Context,
	cfg RelayBridgeConfig,
	b *relay.UDPPairBridge,
	provider RelayTicketProvider,
	run func(context.Context) error,
) error {
	defer func() { _ = b.Close() }()

	backoff := time.Second
	for {
		ticket := cfg.Ticket
		var err error
		if provider != nil {
			ticket, err = provider(ctx)
		}

		if err == nil {
			err = b.Bind(ctx, ticket)
		}

		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil
		}
		if provider == nil {
			return err
		} // Consumed credentials cannot be retried.
		if waitBackoff(ctx, backoff) != nil {
			return nil
		}

		backoff = min(backoff*2, 30*time.Second)
	}

	runCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	if provider != nil && cfg.TicketLifetime > 0 {
		workers.Add(1)
		go func() {
			defer workers.Done()

			delay := renewalDelay(cfg.TicketLifetime)
			for waitBackoff(runCtx, delay) == nil {
				ticket, err := provider(runCtx)
				if err == nil {
					err = b.Bind(runCtx, ticket)
				}

				if err != nil {
					delay = min(max(delay, time.Second)*2, 30*time.Second)
				} else {
					delay = renewalDelay(cfg.TicketLifetime)
				}
			}
		}()
	}

	err := run(runCtx)
	cancel()
	workers.Wait()
	return err
}

func renewalDelay(lifetime time.Duration) time.Duration {
	delay := lifetime - ticketRenewalSkew
	if delay <= 0 {
		delay = lifetime / 2
	}

	return max(delay, time.Millisecond)
}
