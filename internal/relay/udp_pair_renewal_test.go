package relay

import (
	"net"
	"testing"
	"time"

	"github.com/coder/websocket/wsjson"
)

func TestUDPPairRenewalUsesEndpointMappingForRetainedPort(t *testing.T) {
	f := newPairFixture(t, UDPPairConfig{})

	a, b := pairUDP(t), pairUDP(t)

	_, ra := f.bind(t, f.ticket(t, "s", "a", "b"), a)

	_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)

	c, offer := f.offer(t, f.ticket(t, "s", "a", "b"))

	probeAddress, err := net.ResolveUDPAddr("udp", offer.UDPAddress)
	if err != nil {
		t.Fatal(err)
	}

	// Model endpoint-dependent NAT with real distinct UDP egress sockets:
	// the same private socket acquires a different public mapping when the
	// relay destination port changes, and keeps the old mapping otherwise.
	probeSocket := a
	if !sameUDPAddr(probeAddress, ra) {
		probeSocket = pairUDP(t)
	}

	challenge, _ := probePair(t, probeSocket, offer)

	if err := wsjson.Write(
		f.ctx,
		c,
		UDPPairMessage{Protocol: UDPPairProtocol, Kind: "confirm", Challenge: challenge},
	); err != nil {
		t.Fatal(err)
	}

	var bound UDPPairMessage

	if err := wsjson.Read(f.ctx, c, &bound); err != nil {
		t.Fatal(err)
	}

	address, err := net.ResolveUDPAddr("udp", bound.UDPAddress)
	if err != nil {
		t.Fatal(err)
	}

	egress := probeSocket
	if sameUDPAddr(address, ra) {
		egress = a
	}

	sendPair(t, egress, []byte("destination-dependent-mapping"), address)
	readPairRaw(t, b, []byte("destination-dependent-mapping"), rb)
	sendPair(t, b, []byte("return-to-current-mapping"), rb)
	readPairRaw(t, egress, []byte("return-to-current-mapping"), address)
}

func TestUDPPairFailedRenewalCannotCloseEstablishedIngress(t *testing.T) {
	for _, mode := range []string{"cancel", "bad confirm", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := newPairFixture(t, UDPPairConfig{BindTimeout: 300 * time.Millisecond})

			a, b := pairUDP(t), pairUDP(t)

			_, ra := f.bind(t, f.ticket(t, "s", "a", "b"), a)

			_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)

			c, offer := f.offer(t, f.ticket(t, "s", "a", "b"))

			address, err := net.ResolveUDPAddr("udp", offer.UDPAddress)

			if err != nil || !sameUDPAddr(address, ra) {
				t.Fatal("renewal proof moved to a different ingress")
			}

			// Pending proof must not pause or reinterpret existing data traffic.
			sendPair(t, a, []byte("still-established"), ra)
			readPairRaw(t, b, []byte("still-established"), rb)
			if mode == "cancel" {
				_ = c.CloseNow()
			} else {
				if mode == "bad confirm" {
					if err := wsjson.Write(
						f.ctx,
						c,
						UDPPairMessage{
							Protocol:  UDPPairProtocol,
							Kind:      "confirm",
							Challenge: "not-proven",
						},
					); err != nil {
						t.Fatal(err)
					}
				}

				var reply UDPPairMessage

				if err := wsjson.Read(f.ctx, c, &reply); err == nil {
					t.Fatal("invalid/incomplete renewal was confirmed")
				}
			}

			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()

			for {
				f.r.mu.Lock()
				pending := false
				for p := range f.r.all {
					if !p.bound {
						pending = true
					}
				}

				f.r.mu.Unlock()
				if !pending {
					break
				}

				select {
				case <-f.ctx.Done():
					t.Fatal("pending renewal leaked")
				case <-ticker.C:
				}
			}

			sendPair(t, b, []byte("after-renewal-failure"), rb)
			readPairRaw(t, a, []byte("after-renewal-failure"), ra)
		})
	}
}

func TestUDPPairLostRenewalAcknowledgmentPreservesIngress(t *testing.T) {
	for _, roam := range []bool{false, true} {
		name := "same endpoint"
		if roam {
			name = "authenticated rebind"
		}

		t.Run(name, func(t *testing.T) {
			f := newPairFixture(t, UDPPairConfig{})

			a, b := pairUDP(t), pairUDP(t)

			_, ra := f.bind(t, f.ticket(t, "s", "a", "b"), a)

			_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)
			current := a
			if roam {
				current = pairUDP(t)
			}

			c, offer := f.offer(t, f.ticket(t, "s", "a", "b"))

			challenge, _ := probePair(t, current, offer)

			if err := wsjson.Write(
				f.ctx,
				c,
				UDPPairMessage{
					Protocol:  UDPPairProtocol,
					Kind:      "confirm",
					Challenge: challenge,
				},
			); err != nil {
				t.Fatal(err)
			}

			// Wait until the relay commits confirmation, then deliberately discard
			// its bound response. The client knows only its previous ingress.
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()

			for {
				f.r.mu.Lock()
				processed := true
				for p := range f.r.all {
					if p.nonce == offer.Nonce && !p.bound {
						processed = false
					}
				}

				f.r.mu.Unlock()
				if processed {
					break
				}

				select {
				case <-f.ctx.Done():
					t.Fatal("confirm was not processed")
				case <-ticker.C:
				}
			}

			_ = c.CloseNow()

			f.s.Close() // No control connection is available to repair ambiguity.
			sendPair(t, current, []byte("after-lost-bound"), ra)
			readPairRaw(t, b, []byte("after-lost-bound"), rb)
			sendPair(t, b, []byte("return-after-lost-bound"), rb)
			readPairRaw(t, current, []byte("return-after-lost-bound"), ra)
			if roam {
				noPairRaw(t, a)
			}
		})
	}
}
