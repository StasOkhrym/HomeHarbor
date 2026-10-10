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

func TestUDPPairRequiresTLSAndPeerBoundTickets(t *testing.T) {
	i := TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	r, err := NewUDPPair(i, UDPPairConfig{ListenIP: net.ParseIP("127.0.0.1")})
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

	unbound, err := i.issue("s", "a", "", time.Minute)
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

type pairFixture struct {
	r   *UDPPair
	i   TicketIssuer
	s   *httptest.Server
	ctx context.Context
}

func newPairFixture(t *testing.T, cfg UDPPairConfig) *pairFixture {
	t.Helper()
	i := TicketIssuer{Key: []byte("01234567890123456789012345678901")}

	return newPairFixtureIssuer(t, cfg, i)
}

func newPairFixtureIssuer(t *testing.T, cfg UDPPairConfig, i TicketIssuer) *pairFixture {
	t.Helper()
	if cfg.ListenIP == nil {
		cfg.ListenIP = net.ParseIP("127.0.0.1")
	}

	r, err := NewUDPPair(i, cfg)
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewTLSServer(r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(func() { cancel(); _ = r.Close(); s.Close() })
	return &pairFixture{r: r, i: i, s: s, ctx: ctx}
}

func (f *pairFixture) ticket(t *testing.T, session, device, peer string) string {
	t.Helper()

	ticket, err := f.i.IssueForPeer(session, device, peer, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	return ticket
}

func (f *pairFixture) offer(t *testing.T, ticket string) (*websocket.Conn, UDPPairMessage) {
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
	var offer UDPPairMessage

	if err := wsjson.Read(f.ctx, c, &offer); err != nil {
		t.Fatal(err)
	}

	if offer.Protocol != "udp_pair" || offer.Kind != "offer" || offer.Nonce == "" {
		t.Fatalf("invalid offer: %+v", offer)
	}

	return c, offer
}

func probePair(t *testing.T, u *net.UDPConn, offer UDPPairMessage) (string, *net.UDPAddr) {
	t.Helper()

	a, err := net.ResolveUDPAddr("udp", offer.UDPAddress)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := u.WriteToUDP([]byte("HHUP"+offer.Nonce), a); err != nil {
		t.Fatal(err)
	}

	_ = u.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 512)

	n, source, err := u.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}

	if !sameUDPAddr(source, a) || !strings.HasPrefix(string(b[:n]), "HHUC") {
		t.Fatalf("unexpected challenge %q from %s", b[:n], source)
	}

	return string(b[4:n]), a
}

func (f *pairFixture) bind(
	t *testing.T,
	ticket string,
	u *net.UDPConn,
) (UDPPairMessage, *net.UDPAddr) {
	t.Helper()
	c, offer := f.offer(t, ticket)

	challenge, _ := probePair(t, u, offer)

	if err := wsjson.Write(
		f.ctx,
		c,
		UDPPairMessage{Protocol: "udp_pair", Kind: "confirm", Challenge: challenge},
	); err != nil {
		t.Fatal(err)
	}

	var bound UDPPairMessage

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

func pairUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = u.Close() })
	return u
}

func readPairRaw(t *testing.T, u *net.UDPConn, want []byte, source *net.UDPAddr) {
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

func sendPair(t *testing.T, u *net.UDPConn, payload []byte, target *net.UDPAddr) {
	t.Helper()

	if _, err := u.WriteToUDP(payload, target); err != nil {
		t.Fatal(err)
	}
}

func noPairRaw(t *testing.T, u *net.UDPConn) {
	t.Helper()
	_ = u.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	_, _, err := u.ReadFromUDP(make([]byte, 65535))
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("unexpected UDP delivery: %v", err)
	}
}

func TestUDPPairLocksEndpointRejectsCapturedProbeAndForwardsRaw(t *testing.T) {
	f := newPairFixture(t, UDPPairConfig{})

	a, b, attacker := pairUDP(t), pairUDP(t), pairUDP(t)

	ta := f.ticket(t, "s", "a", "b")

	offerA, ra := f.bind(t, ta, a)

	_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)

	if sameUDPAddr(ra, rb) {
		t.Fatal("peers share an ingress listener")
	}

	sendPair(t, attacker, []byte("HHUP"+offerA.Nonce), ra)
	sendPair(t, attacker, []byte("captured-wireguard"), ra)
	noPairRaw(t, attacker)
	noPairRaw(t, b)
	// Even an envelope-looking payload is opaque once the endpoint is locked.
	payload := []byte("HHUP" + offerA.Nonce)

	sendPair(t, a, payload, ra)
	readPairRaw(t, b, payload, rb)
	sendPair(t, b, []byte{0, 255, 2, 0}, rb)
	readPairRaw(t, a, []byte{0, 255, 2, 0}, ra)
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

	roamed := pairUDP(t)

	_, newRA := f.bind(t, f.ticket(t, "s", "a", "b"), roamed)

	sendPair(t, b, []byte("new-path"), rb)
	readPairRaw(t, roamed, []byte("new-path"), newRA)
	noPairRaw(t, a)
}

func TestUDPPairConfirmRequiresReturnChallengeAndAdmissionExpiry(t *testing.T) {
	for _, mode := range []string{"tamper", "no-return", "expired"} {
		t.Run(mode, func(t *testing.T) {
			var offset atomic.Int64
			i := TicketIssuer{
				Key: []byte("01234567890123456789012345678901"),
				Now: func() time.Time { return time.Now().Add(time.Duration(offset.Load()) * time.Second) },
			}

			f := newPairFixtureIssuer(t, UDPPairConfig{}, i)

			u := pairUDP(t)

			c, offer := f.offer(t, f.ticket(t, "s", "a", "b"))
			challenge := "not-a-return-path-challenge"
			if mode != "no-return" {
				challenge, _ = probePair(t, u, offer)
			}

			if mode == "tamper" {
				challenge += "x"
			}

			if mode == "expired" {
				offset.Store(120)
			}

			_ = wsjson.Write(
				f.ctx,
				c,
				UDPPairMessage{Protocol: "udp_pair", Kind: "confirm", Challenge: challenge},
			)
			var reply UDPPairMessage

			if err := wsjson.Read(f.ctx, c, &reply); err == nil {
				t.Fatalf("invalid confirmation accepted: %+v", reply)
			}
		})
	}
}

func TestUDPPairEstablishedSessionSurvivesTicketExpiryAndControlClose(t *testing.T) {
	var offset atomic.Int64
	i := TicketIssuer{
		Key: []byte("01234567890123456789012345678901"),
		Now: func() time.Time { return time.Now().Add(time.Duration(offset.Load()) * time.Second) },
	}

	f := newPairFixtureIssuer(t, UDPPairConfig{}, i)

	a, b := pairUDP(t), pairUDP(t)

	_, ra := f.bind(t, f.ticket(t, "s", "a", "b"), a)

	_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)

	offset.Store(120)
	f.s.Close() // Admission/control outage must not expire the packet plane.
	sendPair(t, a, []byte("after-expiry"), ra)
	readPairRaw(t, b, []byte("after-expiry"), rb)
}

func TestUDPPairBindingTimeoutIdleTimeoutLimitsAndPortReclamation(t *testing.T) {
	portSocket := pairUDP(t)
	port := portSocket.LocalAddr().(*net.UDPAddr).Port

	_ = portSocket.Close()

	f := newPairFixture(
		t,
		UDPPairConfig{
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
	var reply UDPPairMessage

	if err := wsjson.Read(f.ctx, c, &reply); err == nil {
		t.Fatal("binding never timed out")
	}

	// Binding failure must release the sole configured port and session slot.
	u := pairUDP(t)

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

func TestUDPPairOversizeDroppedAndDeviceLimitEnforced(t *testing.T) {
	f := newPairFixture(t, UDPPairConfig{MaxPeersPerDevice: 1, MaxDatagramBytes: 64})

	a, b := pairUDP(t), pairUDP(t)

	_, ra := f.bind(t, f.ticket(t, "s", "a", "b"), a)

	_, rb := f.bind(t, f.ticket(t, "s", "b", "a"), b)

	sendPair(t, a, bytes.Repeat([]byte{1}, 65), ra)
	noPairRaw(t, b)
	sendPair(t, a, bytes.Repeat([]byte{2}, 64), ra)
	readPairRaw(t, b, bytes.Repeat([]byte{2}, 64), rb)
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

func TestUDPPairBoundsTotalListenersAndReplayLedger(t *testing.T) {
	for _, limits := range []UDPPairConfig{{MaxPeers: 1}, {MaxAdmissions: 1}} {
		f := newPairFixture(t, limits)

		_, _ = f.bind(t, f.ticket(t, "s", "a", "b"), pairUDP(t))
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

func TestUDPPairCloseCancelsAndAwaitsPendingTLSBinding(t *testing.T) {
	f := newPairFixture(t, UDPPairConfig{BindTimeout: time.Minute})

	c, offer := f.offer(t, f.ticket(t, "s", "a", "b"))
	closed := make(chan struct{})
	go func() { _ = f.r.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("pending TLS binding prevented shutdown")
	}

	var reply UDPPairMessage

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

func TestUDPPairOwnsStartupListenerAndFailsClosedOnRangeExhaustion(t *testing.T) {
	seed := pairUDP(t)
	port := seed.LocalAddr().(*net.UDPAddr).Port

	f := newPairFixture(t, UDPPairConfig{PortMin: port, PortMax: port})

	if err := f.r.AdoptListener(seed); err != nil {
		t.Fatal(err)
	}

	u := pairUDP(t)

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

func TestUDPPairBridgeRejectsOldControlPath(t *testing.T) {
	cfg := UDPPairBridgeConfig{
		ControlURL:          "wss://relay.example/relay/udp/v2",
		Ticket:              "ticket",
		SessionID:           "s",
		DeviceID:            "a",
		DestinationDeviceID: "b",
		ListenAddress:       &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		WireGuardAddress:    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9},
	}
	if bridge, err := NewUDPPairBridge(cfg); err == nil {
		_ = bridge.Close()

		t.Fatal("old relay path accepted")
	}

	cfg.ControlURL = "wss://relay.example/relay/udp"

	bridge, err := NewUDPPairBridge(cfg)
	if err != nil {
		t.Fatalf("canonical path rejected: %v", err)
	}

	_ = bridge.Close()
}

func TestUDPPairBridgeRejectsPlaintextAndUntrustedTLS(t *testing.T) {
	i := TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	r, err := NewUDPPair(i, UDPPairConfig{ListenIP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	s := httptest.NewTLSServer(r)
	defer func() { s.Close() }()

	ticket, _ := i.IssueForPeer("s", "a", "b", time.Minute)
	cfg := UDPPairBridgeConfig{
		ControlURL:          "ws://127.0.0.1/relay/udp",
		Ticket:              ticket,
		SessionID:           "s",
		DeviceID:            "a",
		DestinationDeviceID: "b",
		ListenAddress:       &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		WireGuardAddress:    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9},
	}
	if b, err := NewUDPPairBridge(cfg); err == nil {
		_ = b.Close()

		t.Fatal("accepted plaintext control URL")
	}

	cfg.ControlURL = "wss" + strings.TrimPrefix(s.URL, "https") + "/relay/udp"

	b, err := NewUDPPairBridge(cfg)
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

func TestUDPPairBridgeNeverLeaksTicketThroughTLSRedirect(t *testing.T) {
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

	b, err := NewUDPPairBridge(
		UDPPairBridgeConfig{
			ControlURL:          "wss" + strings.TrimPrefix(s.URL, "https") + "/relay/udp",
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

func TestUDPPairBridgesRenewWithoutReplacingLocalWireGuardSocket(t *testing.T) {
	f := newPairFixture(t, UDPPairConfig{MaxPeersPerDevice: 1})
	wgA, wgB := pairUDP(t), pairUDP(t)
	makeBridge := func(device, peer string, wg *net.UDPConn) *UDPPairBridge {
		b, err := NewUDPPairBridge(
			UDPPairBridgeConfig{
				ControlURL:          "wss" + strings.TrimPrefix(f.s.URL, "https") + "/relay/udp",
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
	for _, bridge := range []*UDPPairBridge{a, b} {
		select {
		case <-bridge.Connected():
		case err := <-done:
			t.Fatalf("bind failed: %v", err)
		case <-f.ctx.Done():
			t.Fatal("bridge bind timeout")
		}
	}
	aa, ba := a.LocalAddr(), b.LocalAddr()
	sendPair(t, wgA, []byte("wg-before-renewal"), &aa)
	readPairRaw(t, wgB, []byte("wg-before-renewal"), &ba)
	if err := a.Bind(f.ctx, f.ticket(t, "s", "a", "b")); err != nil {
		t.Fatal(err)
	}
	renewedAddr := a.LocalAddr()
	if renewedAddr.String() != aa.String() {
		t.Fatal("ticket renewal replaced WireGuard endpoint")
	}
	sendPair(t, wgB, []byte("wg-after-renewal"), &ba)
	readPairRaw(t, wgA, []byte("wg-after-renewal"), &aa)
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
