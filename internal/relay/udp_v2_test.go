package relay

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func TestUDPV2RequiresTLSAndPeerBoundTickets(t *testing.T) {
	i := TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	r, err := NewUDPPairV2(i, UDPPairV2Config{ListenIP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	plain := httptest.NewServer(r)
	defer func() { plain.Close() }()
	resp, err := http.Get(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plaintext admission status=%d", resp.StatusCode)
	}
	tlsServer := httptest.NewTLSServer(r)
	defer func() { tlsServer.Close() }()
	unbound, err := i.Issue("s", "a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{unbound, unbound + "tampered", ""} {
		req, _ := http.NewRequest(http.MethodGet, tlsServer.URL, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := tlsServer.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("invalid admission status=%d", resp.StatusCode)
		}
	}
}

type v2Fixture struct {
	r   *UDPPairV2
	i   TicketIssuer
	s   *httptest.Server
	ctx context.Context
}

func newV2Fixture(t *testing.T, cfg UDPPairV2Config) *v2Fixture {
	t.Helper()
	i := TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	return newV2FixtureIssuer(t, cfg, i)
}

func newV2FixtureIssuer(t *testing.T, cfg UDPPairV2Config, i TicketIssuer) *v2Fixture {
	t.Helper()
	if cfg.ListenIP == nil {
		cfg.ListenIP = net.ParseIP("127.0.0.1")
	}
	r, err := NewUDPPairV2(i, cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewTLSServer(r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(func() { cancel(); _ = r.Close(); s.Close() })
	return &v2Fixture{r: r, i: i, s: s, ctx: ctx}
}

func (f *v2Fixture) ticket(t *testing.T, session, device, peer string) string {
	t.Helper()
	ticket, err := f.i.IssueForPeer(session, device, peer, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

func (f *v2Fixture) offer(t *testing.T, ticket string) (*websocket.Conn, UDPPairV2Message) {
	t.Helper()
	h := http.Header{"Authorization": {"Bearer " + ticket}}
	c, _, err := websocket.Dial(
		f.ctx,
		"wss"+strings.TrimPrefix(f.s.URL, "https"),
		&websocket.DialOptions{HTTPClient: f.s.Client(), HTTPHeader: h},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	var offer UDPPairV2Message
	if err := wsjson.Read(f.ctx, c, &offer); err != nil {
		t.Fatal(err)
	}
	if offer.Protocol != "udp_pair_v2" || offer.Kind != "offer" || offer.Nonce == "" {
		t.Fatalf("invalid offer: %+v", offer)
	}
	return c, offer
}

func probeV2(t *testing.T, u *net.UDPConn, offer UDPPairV2Message) (string, *net.UDPAddr) {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", offer.UDPAddress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.WriteToUDP([]byte("GTU2P"+offer.Nonce), a); err != nil {
		t.Fatal(err)
	}
	_ = u.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 512)
	n, source, err := u.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	if !sameUDPAddr(source, a) || !strings.HasPrefix(string(b[:n]), "GTU2C") {
		t.Fatalf("unexpected challenge %q from %s", b[:n], source)
	}
	return string(b[5:n]), a
}

func (f *v2Fixture) bind(t *testing.T, ticket string, u *net.UDPConn) (UDPPairV2Message, *net.UDPAddr) {
	t.Helper()
	c, offer := f.offer(t, ticket)
	challenge, _ := probeV2(t, u, offer)
	if err := wsjson.Write(
		f.ctx,
		c,
		UDPPairV2Message{Protocol: "udp_pair_v2", Kind: "confirm", Challenge: challenge},
	); err != nil {
		t.Fatal(err)
	}
	var bound UDPPairV2Message
	if err := wsjson.Read(f.ctx, c, &bound); err != nil {
		t.Fatal(err)
	}
	if bound.Kind != "bound" || bound.ObservedEndpoint != u.LocalAddr().String() {
		t.Fatalf("binding not confirmed: %+v", bound)
	}
	_ = c.CloseNow()
	a, err := net.ResolveUDPAddr("udp", bound.UDPAddress)
	if err != nil || a.Port == 0 {
		t.Fatalf("invalid confirmed data ingress: %s", bound.UDPAddress)
	}
	return offer, a
}

func v2UDP(t *testing.T) *net.UDPConn {
	t.Helper()
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Close() })
	return u
}

func readV2Raw(t *testing.T, u *net.UDPConn, want []byte, source *net.UDPAddr) {
	t.Helper()
	_ = u.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 65535)
	n, from, err := u.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[:n], want) || !sameUDPAddr(from, source) {
		t.Fatalf("raw bytes=%q from=%s, want=%q from=%s", b[:n], from, want, source)
	}
}

func sendV2(t *testing.T, u *net.UDPConn, payload []byte, target *net.UDPAddr) {
	t.Helper()
	if _, err := u.WriteToUDP(payload, target); err != nil {
		t.Fatal(err)
	}
}

func noV2Raw(t *testing.T, u *net.UDPConn) {
	t.Helper()
	_ = u.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _, err := u.ReadFromUDP(make([]byte, 65535))
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("unexpected UDP delivery: %v", err)
	}
}

func TestUDPV2LocksEndpointRejectsCapturedProbeAndForwardsRaw(t *testing.T) {
	f := newV2Fixture(t, UDPPairV2Config{})
	a, b, attacker := v2UDP(t), v2UDP(t), v2UDP(t)
	ta := f.ticket(t, "s", "a", "b")
	offerA, ra := f.bind(t, ta, a)
	_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)
	if sameUDPAddr(ra, rb) {
		t.Fatal("peers share an ingress listener")
	}
	sendV2(t, attacker, []byte("GTU2P"+offerA.Nonce), ra)
	sendV2(t, attacker, []byte("captured-wireguard"), ra)
	noV2Raw(t, attacker)
	noV2Raw(t, b)
	// Even an envelope-looking payload is opaque once the endpoint is locked.
	payload := []byte("GTU2P" + offerA.Nonce)
	sendV2(t, a, payload, ra)
	readV2Raw(t, b, payload, rb)
	sendV2(t, b, []byte{0, 255, 2, 0}, rb)
	readV2Raw(t, a, []byte{0, 255, 2, 0}, ra)
	// A captured nonce/UDP packet cannot reauthenticate over WSS.
	h := http.Header{"Authorization": {"Bearer " + ta}}
	c, resp, err := websocket.Dial(
		f.ctx,
		"wss"+strings.TrimPrefix(f.s.URL, "https"),
		&websocket.DialOptions{HTTPClient: f.s.Client(), HTTPHeader: h},
	)
	if c != nil {
		_ = c.CloseNow()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusConflict {
		t.Fatalf("replayed ticket admitted: %v %+v", err, resp)
	}
	roamed := v2UDP(t)
	_, newRA := f.bind(t, f.ticket(t, "s", "a", "b"), roamed)
	sendV2(t, b, []byte("new-path"), rb)
	readV2Raw(t, roamed, []byte("new-path"), newRA)
	noV2Raw(t, a)
}

func TestUDPV2ConfirmRequiresReturnChallengeAndAdmissionExpiry(t *testing.T) {
	for _, mode := range []string{"tamper", "no-return", "expired"} {
		t.Run(mode, func(t *testing.T) {
			var offset atomic.Int64
			i := TicketIssuer{
				Key: []byte("01234567890123456789012345678901"),
				Now: func() time.Time { return time.Now().Add(time.Duration(offset.Load()) * time.Second) },
			}
			f := newV2FixtureIssuer(t, UDPPairV2Config{}, i)
			u := v2UDP(t)
			c, offer := f.offer(t, f.ticket(t, "s", "a", "b"))
			challenge := "not-a-return-path-challenge"
			if mode != "no-return" {
				challenge, _ = probeV2(t, u, offer)
			}
			if mode == "tamper" {
				challenge += "x"
			}
			if mode == "expired" {
				offset.Store(120)
			}
			_ = wsjson.Write(f.ctx, c, UDPPairV2Message{Protocol: "udp_pair_v2", Kind: "confirm", Challenge: challenge})
			var reply UDPPairV2Message
			if err := wsjson.Read(f.ctx, c, &reply); err == nil {
				t.Fatalf("invalid confirmation accepted: %+v", reply)
			}
		})
	}
}

func TestUDPV2EstablishedSessionSurvivesTicketExpiryAndControlClose(t *testing.T) {
	var offset atomic.Int64
	i := TicketIssuer{
		Key: []byte("01234567890123456789012345678901"),
		Now: func() time.Time { return time.Now().Add(time.Duration(offset.Load()) * time.Second) },
	}
	f := newV2FixtureIssuer(t, UDPPairV2Config{}, i)
	a, b := v2UDP(t), v2UDP(t)
	_, ra := f.bind(t, f.ticket(t, "s", "a", "b"), a)
	_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)
	offset.Store(120)
	f.s.Close() // Admission/control outage must not expire the packet plane.
	sendV2(t, a, []byte("after-expiry"), ra)
	readV2Raw(t, b, []byte("after-expiry"), rb)
}

func TestUDPV2BindingTimeoutIdleTimeoutLimitsAndPortReclamation(t *testing.T) {
	portSocket := v2UDP(t)
	port := portSocket.LocalAddr().(*net.UDPAddr).Port
	_ = portSocket.Close()
	f := newV2Fixture(
		t,
		UDPPairV2Config{
			PortMin:           port,
			PortMax:           port,
			BindTimeout:       80 * time.Millisecond,
			IdleTimeout:       120 * time.Millisecond,
			MaxPeers:          2,
			MaxPeersPerDevice: 1,
			MaxDatagramBytes:  64,
		},
	)
	c, _ := f.offer(t, f.ticket(t, "s", "a", "b"))
	var reply UDPPairV2Message
	if err := wsjson.Read(f.ctx, c, &reply); err == nil {
		t.Fatal("binding never timed out")
	}
	// Binding failure must release the sole configured port and session slot.
	u := v2UDP(t)
	_, address := f.bind(t, f.ticket(t, "s", "a", "b"), u)
	if address.Port != port {
		t.Fatalf("port=%d, want configured %d", address.Port, port)
	}
	time.Sleep(180 * time.Millisecond)
	_, _ = f.bind(t, f.ticket(t, "s", "a", "b"), u)
	_ = f.r.Close()
	reclaimed, err := net.ListenUDP("udp", address)
	if err != nil {
		t.Fatalf("port leaked after Close: %v", err)
	}
	_ = reclaimed.Close()
}

func TestUDPV2OversizeDroppedAndDeviceLimitEnforced(t *testing.T) {
	f := newV2Fixture(t, UDPPairV2Config{MaxPeersPerDevice: 1, MaxDatagramBytes: 64})
	a, b := v2UDP(t), v2UDP(t)
	_, ra := f.bind(t, f.ticket(t, "s", "a", "b"), a)
	_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)
	sendV2(t, a, bytes.Repeat([]byte{1}, 65), ra)
	noV2Raw(t, b)
	sendV2(t, a, bytes.Repeat([]byte{2}, 64), ra)
	readV2Raw(t, b, bytes.Repeat([]byte{2}, 64), rb)
	h := http.Header{"Authorization": {"Bearer " + f.ticket(t, "s2", "a", "c")}}
	c, resp, err := websocket.Dial(
		f.ctx,
		"wss"+strings.TrimPrefix(f.s.URL, "https"),
		&websocket.DialOptions{HTTPClient: f.s.Client(), HTTPHeader: h},
	)
	if c != nil {
		_ = c.CloseNow()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("per-device session limit bypassed: %v %+v", err, resp)
	}
}

func TestUDPV2BoundsTotalListenersAndReplayLedger(t *testing.T) {
	for _, limits := range []UDPPairV2Config{{MaxPeers: 1}, {MaxAdmissions: 1}} {
		f := newV2Fixture(t, limits)
		_, _ = f.bind(t, f.ticket(t, "s", "a", "b"), v2UDP(t))
		h := http.Header{"Authorization": {"Bearer " + f.ticket(t, "s2", "c", "d")}}
		c, resp, err := websocket.Dial(
			f.ctx,
			"wss"+strings.TrimPrefix(f.s.URL, "https"),
			&websocket.DialOptions{HTTPClient: f.s.Client(), HTTPHeader: h},
		)
		if c != nil {
			_ = c.CloseNow()
		}
		if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("global resource limit bypassed: %v %+v", err, resp)
		}
	}
}

func TestUDPV2CloseCancelsAndAwaitsPendingTLSBinding(t *testing.T) {
	f := newV2Fixture(t, UDPPairV2Config{BindTimeout: time.Minute})
	c, offer := f.offer(t, f.ticket(t, "s", "a", "b"))
	closed := make(chan struct{})
	go func() { _ = f.r.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("pending TLS binding prevented shutdown")
	}
	var reply UDPPairV2Message
	if err := wsjson.Read(f.ctx, c, &reply); err == nil {
		t.Fatal("control handshake remained open after shutdown")
	}
	address, err := net.ResolveUDPAddr("udp", offer.UDPAddress)
	if err != nil {
		t.Fatal(err)
	}
	u, err := net.ListenUDP("udp", address)
	if err != nil {
		t.Fatalf("pending listener leaked: %v", err)
	}
	_ = u.Close()
}

func TestUDPV2OwnsStartupListenerAndFailsClosedOnRangeExhaustion(t *testing.T) {
	seed := v2UDP(t)
	port := seed.LocalAddr().(*net.UDPAddr).Port
	f := newV2Fixture(t, UDPPairV2Config{PortMin: port, PortMax: port})
	if err := f.r.AdoptListener(seed); err != nil {
		t.Fatal(err)
	}
	u := v2UDP(t)
	_, a := f.bind(t, f.ticket(t, "s", "a", "b"), u)
	if a.Port != port {
		t.Fatal("startup listener not used for authenticated admission")
	}
	h := http.Header{"Authorization": {"Bearer " + f.ticket(t, "s", "b", "a")}}
	c, resp, err := websocket.Dial(
		f.ctx,
		"wss"+strings.TrimPrefix(f.s.URL, "https"),
		&websocket.DialOptions{HTTPClient: f.s.Client(), HTTPHeader: h},
	)
	if c != nil {
		_ = c.CloseNow()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("range exhaustion bypassed: %v %+v", err, resp)
	}
	_ = f.r.Close()
	reclaimed, err := net.ListenUDP("udp", a)
	if err != nil {
		t.Fatalf("adopted listener leaked: %v", err)
	}
	_ = reclaimed.Close()
}

func TestUDPV2BridgeRejectsPlaintextAndUntrustedTLS(t *testing.T) {
	i := TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	r, err := NewUDPPairV2(i, UDPPairV2Config{ListenIP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	s := httptest.NewTLSServer(r)
	defer func() { s.Close() }()
	ticket, _ := i.IssueForPeer("s", "a", "b", time.Minute)
	cfg := UDPPairV2BridgeConfig{
		ControlURL:          "ws://127.0.0.1/relay/udp/v2",
		Ticket:              ticket,
		SessionID:           "s",
		DeviceID:            "a",
		DestinationDeviceID: "b",
		ListenAddress:       &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		WireGuardAddress:    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9},
	}
	if b, err := NewUDPPairV2Bridge(cfg); err == nil {
		_ = b.Close()
		t.Fatal("accepted plaintext control URL")
	}
	cfg.ControlURL = "wss" + strings.TrimPrefix(s.URL, "https")
	b, err := NewUDPPairV2Bridge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Bind(ctx, ticket); err == nil {
		t.Fatal("accepted untrusted TLS certificate")
	}
}

func TestUDPV2BridgeNeverLeaksTicketThroughTLSRedirect(t *testing.T) {
	leaked := make(chan string, 1)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer func() { plain.Close() }()
	s := httptest.NewTLSServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, plain.URL, http.StatusFound) },
		),
	)
	defer func() { s.Close() }()
	b, err := NewUDPPairV2Bridge(
		UDPPairV2BridgeConfig{
			ControlURL:          "wss" + strings.TrimPrefix(s.URL, "https"),
			HTTPClient:          s.Client(),
			Ticket:              "secret",
			SessionID:           "s",
			DeviceID:            "a",
			DestinationDeviceID: "b",
			ListenAddress:       &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
			WireGuardAddress:    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Bind(ctx, "secret"); err == nil {
		t.Fatal("redirect admission succeeded")
	}
	select {
	case auth := <-leaked:
		t.Fatalf("TLS redirect exposed bearer ticket: %q", auth)
	default:
	}
}

func TestUDPV2BridgesRenewWithoutReplacingLocalWireGuardSocket(t *testing.T) {
	f := newV2Fixture(t, UDPPairV2Config{MaxPeersPerDevice: 1})
	wgA, wgB := v2UDP(t), v2UDP(t)
	makeBridge := func(device, peer string, wg *net.UDPConn) *UDPPairV2Bridge {
		b, err := NewUDPPairV2Bridge(
			UDPPairV2BridgeConfig{
				ControlURL:          "wss" + strings.TrimPrefix(f.s.URL, "https"),
				HTTPClient:          f.s.Client(),
				Ticket:              f.ticket(t, "s", device, peer),
				SessionID:           "s",
				DeviceID:            device,
				DestinationDeviceID: peer,
				ListenAddress:       &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
				WireGuardAddress:    wg.LocalAddr().(*net.UDPAddr),
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.Close() })
		return b
	}
	a, b := makeBridge("a", "b", wgA), makeBridge("b", "a", wgB)
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 2)
	go func() { done <- a.Run(ctx) }()
	go func() { done <- b.Run(ctx) }()
	for _, bridge := range []*UDPPairV2Bridge{a, b} {
		select {
		case <-bridge.Connected():
		case err := <-done:
			t.Fatalf("bind failed: %v", err)
		case <-f.ctx.Done():
			t.Fatal("bridge bind timeout")
		}
	}
	aa, ba := a.LocalAddr(), b.LocalAddr()
	sendV2(t, wgA, []byte("wg-before-renewal"), &aa)
	readV2Raw(t, wgB, []byte("wg-before-renewal"), &ba)
	if err := a.Bind(f.ctx, f.ticket(t, "s", "a", "b")); err != nil {
		t.Fatal(err)
	}
	renewedAddr := a.LocalAddr()
	if renewedAddr.String() != aa.String() {
		t.Fatal("ticket renewal replaced WireGuard endpoint")
	}
	sendV2(t, wgB, []byte("wg-after-renewal"), &ba)
	readV2Raw(t, wgA, []byte("wg-after-renewal"), &aa)
	cancel()
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("bridge worker not awaited")
		}
	}
	for _, addr := range []*net.UDPAddr{&aa, &ba} {
		u, err := net.ListenUDP("udp", addr)
		if err != nil {
			t.Fatalf("local socket leaked: %v", err)
		}
		_ = u.Close()
	}
}
