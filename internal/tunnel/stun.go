package tunnel

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/pion/stun/v3"

	controlprotocol "github.com/StasOkhrym/homeharbor/internal/protocol"
)

func DiscoverServerReflexive(
	ctx context.Context,
	serverURI string,
) (controlprotocol.Candidate, error) {
	uri, err := stun.ParseURI(serverURI)
	if err != nil {
		return controlprotocol.Candidate{}, fmt.Errorf("parse STUN URI: %w", err)
	}
	client, err := stun.DialURI(uri, &stun.DialConfig{})
	if err != nil {
		return controlprotocol.Candidate{}, fmt.Errorf("dial STUN: %w", err)
	}
	defer func() { _ = client.Close() }()
	request, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return controlprotocol.Candidate{}, err
	}
	// Pion delivers the transaction result from its read loop. Buffering the
	// channel prevents that loop from blocking if the caller's context expires.
	result := make(chan struct {
		candidate controlprotocol.Candidate
		err       error
	}, 1)
	if err = client.Do(request, func(event stun.Event) {
		if event.Error != nil {
			result <- struct {
				candidate controlprotocol.Candidate
				err       error
			}{err: event.Error}
			return
		}
		var address stun.XORMappedAddress
		if parseErr := event.Message.Parse(&address); parseErr != nil {
			result <- struct {
				candidate controlprotocol.Candidate
				err       error
			}{err: parseErr}
			return
		}
		ip, parseErr := netip.ParseAddr(address.IP.String())
		if parseErr != nil {
			result <- struct {
				candidate controlprotocol.Candidate
				err       error
			}{err: parseErr}
			return
		}
		result <- struct {
			candidate controlprotocol.Candidate
			err       error
		}{candidate: controlprotocol.Candidate{Type: controlprotocol.CandidateServerReflexive, Address: netip.AddrPortFrom(ip, uint16(address.Port)).String(), Priority: 100}}
	}); err != nil {
		return controlprotocol.Candidate{}, fmt.Errorf("STUN binding: %w", err)
	}
	select {
	case <-ctx.Done():
		return controlprotocol.Candidate{}, ctx.Err()
	case value := <-result:
		if value.err != nil {
			return controlprotocol.Candidate{}, fmt.Errorf("STUN response: %w", value.err)
		}
		return value.candidate, nil
	}
}
