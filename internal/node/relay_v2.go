package node

import (
	"context"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/relay"
)

func usesUDPV2(cfg RelayBridgeConfig) bool {
	if cfg.RelayTransport == relay.UDPPairV2Protocol {
		return true
	}
	u, err := url.Parse(cfg.RelayURL)
	return err == nil && u.Path == "/relay/udp/v2"
}

func newUDPV2Bridge(cfg RelayBridgeConfig) (*relay.UDPPairV2Bridge, error) {
	listen, err := net.ResolveUDPAddr("udp", cfg.ListenAddress)
	if err != nil {
		return nil, err
	}
	wg, err := net.ResolveUDPAddr("udp", cfg.WireGuardAddress)
	if err != nil {
		return nil, err
	}
	return relay.NewUDPPairV2Bridge(
		relay.UDPPairV2BridgeConfig{
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

// runUDPV2Owner retains the local endpoint through admission retries and
// renewal outages. It owns the renewal worker and awaits it before returning.
// A credential's lifetime schedules authentication; it never bounds Run.
func runUDPV2Owner(
	ctx context.Context,
	cfg RelayBridgeConfig,
	b *relay.UDPPairV2Bridge,
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
			delay := v2RenewalDelay(cfg.TicketLifetime)
			for waitBackoff(runCtx, delay) == nil {
				ticket, err := provider(runCtx)
				if err == nil {
					err = b.Bind(runCtx, ticket)
				}
				if err != nil {
					delay = min(max(delay, time.Second)*2, 30*time.Second)
				} else {
					delay = v2RenewalDelay(cfg.TicketLifetime)
				}
			}
		}()
	}
	err := run(runCtx)
	cancel()
	workers.Wait()
	return err
}

func v2RenewalDelay(lifetime time.Duration) time.Duration {
	delay := lifetime - ticketRenewalSkew
	if delay <= 0 {
		delay = lifetime / 2
	}
	return max(delay, time.Millisecond)
}
