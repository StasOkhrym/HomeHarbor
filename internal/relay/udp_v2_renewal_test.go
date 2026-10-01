package relay

import (
	"net"
	"testing"
	"time"

	"github.com/coder/websocket/wsjson"
)

func TestUDPV2RenewalUsesEndpointMappingForRetainedPort(t *testing.T) {
	f := newV2Fixture(t, UDPPairV2Config{})
	a, b := v2UDP(t), v2UDP(t)
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
		probeSocket = v2UDP(t)
	}
	challenge, _ := probeV2(t, probeSocket, offer)
	if err := wsjson.Write(
		f.ctx,
		c,
		UDPPairV2Message{Protocol: UDPPairV2Protocol, Kind: "confirm", Challenge: challenge},
	); err != nil {
		t.Fatal(err)
	}
	var bound UDPPairV2Message
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
	sendV2(t, egress, []byte("destination-dependent-mapping"), address)
	readV2Raw(t, b, []byte("destination-dependent-mapping"), rb)
	sendV2(t, b, []byte("return-to-current-mapping"), rb)
	readV2Raw(t, egress, []byte("return-to-current-mapping"), address)
}

func TestUDPV2FailedRenewalCannotCloseEstablishedIngress(t *testing.T) {
	for _, mode := range []string{"cancel", "bad confirm", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := newV2Fixture(t, UDPPairV2Config{BindTimeout: 300 * time.Millisecond})
			a, b := v2UDP(t), v2UDP(t)
			_, ra := f.bind(t, f.ticket(t, "s", "a", "b"), a)
			_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)
			c, offer := f.offer(t, f.ticket(t, "s", "a", "b"))
			address, err := net.ResolveUDPAddr("udp", offer.UDPAddress)
			if err != nil || !sameUDPAddr(address, ra) {
				t.Fatal("renewal proof moved to a different ingress")
			}
			// Pending proof must not pause or reinterpret existing data traffic.
			sendV2(t, a, []byte("still-established"), ra)
			readV2Raw(t, b, []byte("still-established"), rb)
			if mode == "cancel" {
				_ = c.CloseNow()
			} else {
				if mode == "bad confirm" {
					if err := wsjson.Write(
						f.ctx,
						c,
						UDPPairV2Message{Protocol: UDPPairV2Protocol, Kind: "confirm", Challenge: "not-proven"},
					); err != nil {
						t.Fatal(err)
					}
				}
				var reply UDPPairV2Message
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
			sendV2(t, b, []byte("after-renewal-failure"), rb)
			readV2Raw(t, a, []byte("after-renewal-failure"), ra)
		})
	}
}

func TestUDPV2LostRenewalAcknowledgmentPreservesIngress(t *testing.T) {
	for _, roam := range []bool{false, true} {
		name := "same endpoint"
		if roam {
			name = "authenticated rebind"
		}
		t.Run(name, func(t *testing.T) {
			f := newV2Fixture(t, UDPPairV2Config{})
			a, b := v2UDP(t), v2UDP(t)
			_, ra := f.bind(t, f.ticket(t, "s", "a", "b"), a)
			_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)
			current := a
			if roam {
				current = v2UDP(t)
			}
			c, offer := f.offer(t, f.ticket(t, "s", "a", "b"))
			challenge, _ := probeV2(t, current, offer)
			if err := wsjson.Write(
				f.ctx,
				c,
				UDPPairV2Message{Protocol: UDPPairV2Protocol, Kind: "confirm", Challenge: challenge},
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
			sendV2(t, current, []byte("after-lost-bound"), ra)
			readV2Raw(t, b, []byte("after-lost-bound"), rb)
			sendV2(t, b, []byte("return-after-lost-bound"), rb)
			readV2Raw(t, current, []byte("return-after-lost-bound"), ra)
			if roam {
				noV2Raw(t, a)
			}
		})
	}
}
