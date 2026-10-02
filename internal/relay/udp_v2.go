package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const UDPPairV2Protocol = "udp_pair_v2"

// UDPPairV2Config bounds admission and packet-plane resources. Zero ports use
// the operating system's ephemeral allocator range, with MaxPeers as the hard
// socket bound. A configured range is inclusive and never falls back to :0.
type UDPPairV2Config struct {
	ListenIP          net.IP
	AdvertiseHost     string
	PortMin           int
	PortMax           int
	BindTimeout       time.Duration
	IdleTimeout       time.Duration
	MaxPeers          int
	MaxPeersPerDevice int
	MaxDatagramBytes  int
	MaxAdmissions     int
	AllowedOrigins    []string
}

// UDPPairV2Message is the TLS control protocol. UDP uses only HHU2P + nonce
// during admission and HHU2C + challenge for return-path validation. Following
// confirmation data datagrams are opaque. During authenticated renewal only
// the exact outstanding probe nonce is reserved, not an arbitrary UDP prefix.
type UDPPairV2Message struct {
	Protocol            string `json:"protocol"`
	Kind                string `json:"kind"`
	SessionID           string `json:"session_id,omitempty"`
	DeviceID            string `json:"device_id,omitempty"`
	DestinationDeviceID string `json:"destination_device_id,omitempty"`
	UDPAddress          string `json:"udp_address,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	Challenge           string `json:"challenge,omitempty"`
	ObservedEndpoint    string `json:"observed_endpoint,omitempty"`
}

type (
	v2PeerKey struct{ session, device string }
	v2Peer    struct {
		key                  v2PeerKey
		destination          string
		udp                  *net.UDPConn
		nonce, challenge     string
		candidate, endpoint  *net.UDPAddr
		deadline, lastSeen   time.Time
		probes               int
		bound                bool
		probeParent, pending *v2Peer
	}
)

// UDPPairV2 owns every reserved UDP listener, control handshake, and worker.
// Close cancels and awaits them. Ticket verification is admission-only; the
// established packet plane continues until idle expiry, replacement, or Close.
type UDPPairV2 struct {
	cfg       UDPPairV2Config
	tickets   TicketIssuer
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	started   bool
	spare     *net.UDPConn
	peers     map[v2PeerKey]*v2Peer
	all       map[*v2Peer]struct{}
	used      map[[32]byte]int64
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func NewUDPPairV2(tickets TicketIssuer, cfg UDPPairV2Config) (*UDPPairV2, error) {
	if len(tickets.Key) < 32 {
		return nil, errors.New("UDP v2 ticket key must be at least 32 bytes")
	}
	if cfg.PortMin < 0 || cfg.PortMax > 65535 || cfg.PortMax < cfg.PortMin ||
		(cfg.PortMin == 0) != (cfg.PortMax == 0) {
		return nil, errors.New("invalid UDP v2 port range")
	}
	if cfg.BindTimeout == 0 {
		cfg.BindTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 2 * time.Minute
	}
	if cfg.MaxPeers == 0 {
		cfg.MaxPeers = 4096
	}
	if cfg.MaxPeersPerDevice == 0 {
		cfg.MaxPeersPerDevice = 8
	}
	if cfg.MaxDatagramBytes == 0 {
		cfg.MaxDatagramBytes = 65507
	}
	if cfg.MaxAdmissions == 0 {
		cfg.MaxAdmissions = cfg.MaxPeers * 4
	}
	if cfg.BindTimeout < 0 || cfg.IdleTimeout < 0 || cfg.MaxPeers < 1 ||
		cfg.MaxPeersPerDevice < 1 ||
		cfg.MaxAdmissions < 1 ||
		cfg.MaxDatagramBytes < 1 ||
		cfg.MaxDatagramBytes > 65507 {
		return nil, errors.New("invalid UDP v2 resource limits")
	}
	cfg.ListenIP = append(net.IP(nil), cfg.ListenIP...)
	cfg.AllowedOrigins = append([]string(nil), cfg.AllowedOrigins...)
	ctx, cancel := context.WithCancel(context.Background())
	r := &UDPPairV2{
		cfg:     cfg,
		tickets: tickets,
		ctx:     ctx,
		cancel:  cancel,
		peers:   make(map[v2PeerKey]*v2Peer),
		all:     make(map[*v2Peer]struct{}),
		used:    make(map[[32]byte]int64),
	}
	return r, nil
}

func (r *UDPPairV2) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.cancel()
		if r.spare != nil {
			_ = r.spare.Close()
			r.spare = nil
		}
		for p := range r.all {
			r.removeLocked(p)
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
	return nil
}

func (r *UDPPairV2) Run(ctx context.Context) error {
	r.mu.Lock()
	if !r.closed {
		r.startLocked()
	}
	r.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-r.ctx.Done():
	}
	return r.Close()
}

func (r *UDPPairV2) startLocked() {
	if r.started {
		return
	}
	r.started = true
	r.wg.Add(1)
	go r.expire()
}

// AdoptListener transfers a startup/readiness socket to the allocator. It is
// unread until a TLS-authenticated peer reserves it; UDP alone admits nobody.
func (r *UDPPairV2) AdoptListener(udp *net.UDPConn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if udp == nil || r.closed || r.spare != nil || len(r.all) != 0 {
		return errors.New("cannot adopt UDP v2 startup listener")
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	if r.cfg.PortMin != 0 && (port < r.cfg.PortMin || port > r.cfg.PortMax) {
		return errors.New("startup listener outside UDP v2 range")
	}
	r.spare = udp
	return nil
}

func (r *UDPPairV2) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.TLS == nil {
		http.Error(w, "TLS relay control required", http.StatusUpgradeRequired)
		return
	}
	token := relayTicketFromRequest(req)
	claims, err := r.tickets.Verify(token)
	if err != nil || claims.TicketID == "" || claims.DestinationDeviceID == "" ||
		claims.DeviceID == claims.DestinationDeviceID {
		http.Error(w, "invalid peer admission ticket", http.StatusUnauthorized)
		return
	}
	// Add under the same lock that guards Close, so Wait cannot race Add.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		http.Error(w, "relay stopped", http.StatusServiceUnavailable)
		return
	}
	r.wg.Add(1)
	r.mu.Unlock()
	defer r.wg.Done()
	p, status, err := r.reserve(claims, token)
	if err != nil {
		http.Error(w, "relay admission rejected", status)
		return
	}
	defer func() {
		r.mu.Lock()
		if !p.bound {
			r.removeLocked(p)
		}
		r.mu.Unlock()
	}()
	c, err := websocket.Accept(
		w,
		req,
		&websocket.AcceptOptions{
			OriginPatterns:  r.cfg.AllowedOrigins,
			CompressionMode: websocket.CompressionDisabled,
		},
	)
	if err != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(2048)
	ctx, cancel := context.WithDeadline(r.ctx, p.deadline)
	defer cancel()
	stop := context.AfterFunc(req.Context(), cancel)
	defer stop()
	host := r.cfg.AdvertiseHost
	if host == "" {
		if r.cfg.ListenIP != nil && !r.cfg.ListenIP.IsUnspecified() {
			host = r.cfg.ListenIP.String()
		} else {
			host, _, err = net.SplitHostPort(req.Host)
			if err != nil {
				host = req.Host
			}
		}
	}
	address := net.JoinHostPort(host, strconv.Itoa(p.udp.LocalAddr().(*net.UDPAddr).Port))
	offer := UDPPairV2Message{
		Protocol:            UDPPairV2Protocol,
		Kind:                "offer",
		SessionID:           claims.SessionID,
		DeviceID:            claims.DeviceID,
		DestinationDeviceID: claims.DestinationDeviceID,
		UDPAddress:          address,
		Nonce:               p.nonce,
	}
	if err := wsjson.Write(ctx, c, offer); err != nil {
		return
	}
	var confirm UDPPairV2Message
	if err := wsjson.Read(ctx, c, &confirm); err != nil {
		return
	}
	if _, err := r.tickets.Verify(token); err != nil {
		return
	}
	r.mu.Lock()
	_, alive := r.all[p]
	valid := alive && !r.closed && time.Now().Before(p.deadline) && p.candidate != nil &&
		confirm.Protocol == UDPPairV2Protocol &&
		confirm.Kind == "confirm" &&
		subtle.ConstantTimeCompare([]byte(confirm.Challenge), []byte(p.challenge)) == 1
	if !valid {
		r.mu.Unlock()
		return
	}
	active := p
	if old := r.peers[p.key]; old != nil {
		// Preserve the established ingress across an ambiguous WSS response.
		// Return-path proof uses this same socket: endpoint-dependent NAT may
		// choose a different source mapping for every relay destination port.
		// Losing "bound" then leaves the client's known port usable.
		active = old
		r.removeLocked(p)
	} else {
		r.peers[p.key] = p
	}
	active.endpoint = cloneUDPAddr(p.candidate)
	active.bound = true
	active.lastSeen = time.Now()
	observed := active.endpoint.String()
	boundAddress := net.JoinHostPort(host, strconv.Itoa(active.udp.LocalAddr().(*net.UDPAddr).Port))
	r.mu.Unlock()
	// The WSS exchange intentionally ends after acknowledgement. UDP ownership
	// belongs to the relay runtime, not the request or the admission credential.
	_ = wsjson.Write(
		ctx,
		c,
		UDPPairV2Message{
			Protocol:         UDPPairV2Protocol,
			Kind:             "bound",
			ObservedEndpoint: observed,
			UDPAddress:       boundAddress,
		},
	)
}

func (r *UDPPairV2) reserve(c TicketClaims, token string) (*v2Peer, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, http.StatusServiceUnavailable, errors.New("relay stopped")
	}
	key := v2PeerKey{c.SessionID, c.DeviceID}
	fingerprint := sha256.Sum256([]byte(token))
	r.pruneLocked(time.Now())
	if _, ok := r.used[fingerprint]; ok {
		return nil, http.StatusConflict, errors.New("ticket already consumed")
	}
	if len(r.all) >= r.cfg.MaxPeers || len(r.used) >= r.cfg.MaxAdmissions {
		return nil, http.StatusTooManyRequests, errors.New("relay resource limit")
	}
	deviceSessions := make(map[v2PeerKey]struct{})
	for p := range r.all {
		if p.key.device == c.DeviceID {
			deviceSessions[p.key] = struct{}{}
		}
		if p.key.session == c.SessionID && p.key.device != c.DeviceID &&
			(p.key.device != c.DestinationDeviceID || p.destination != c.DeviceID) {
			return nil, http.StatusForbidden, errors.New("not a mutual peer pair")
		}
		if p.key == key && (!p.bound || p.destination != c.DestinationDeviceID) {
			return nil, http.StatusConflict, errors.New("conflicting peer admission")
		}
	}
	if _, existing := deviceSessions[key]; !existing &&
		len(deviceSessions) >= r.cfg.MaxPeersPerDevice {
		return nil, http.StatusTooManyRequests, errors.New("device session limit")
	}
	nonce, err := v2Random()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	challenge, err := v2Random()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	parent := r.peers[key]
	var u *net.UDPConn
	if parent != nil {
		u = parent.udp
	} else {
		u, err = r.listenLocked()
		if err != nil {
			return nil, http.StatusServiceUnavailable, err
		}
	}
	p := &v2Peer{
		key:         key,
		destination: c.DestinationDeviceID,
		udp:         u,
		nonce:       nonce,
		challenge:   challenge,
		deadline:    time.Now().Add(r.cfg.BindTimeout),
		probeParent: parent,
	}
	r.all[p] = struct{}{}
	r.used[fingerprint] = c.ExpiresAt
	r.startLocked()
	if parent != nil {
		// A borrowed ingress has exactly one UDP reader. That reader handles
		// both existing data and the bounded renewal probe under the same lock.
		parent.pending = p
	} else {
		r.wg.Add(1)
		go r.readPeer(p)
	}
	return p, 0, nil
}

func (r *UDPPairV2) listenLocked() (*net.UDPConn, error) {
	if r.spare != nil {
		udp := r.spare
		r.spare = nil
		return udp, nil
	}
	if r.cfg.PortMin == 0 {
		return net.ListenUDP("udp", &net.UDPAddr{IP: r.cfg.ListenIP})
	}
	for port := r.cfg.PortMin; port <= r.cfg.PortMax; port++ {
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: r.cfg.ListenIP, Port: port})
		if err == nil {
			return u, nil
		}
	}
	return nil, errors.New("UDP v2 listener range exhausted")
}

func v2Random() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("UDP v2 nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(nonce[:]), nil
}

func (r *UDPPairV2) readPeer(p *v2Peer) {
	defer r.wg.Done()
	defer func() { r.mu.Lock(); r.removeLocked(p); r.mu.Unlock() }()
	// Read the entire datagram so oversize input is rejected, never truncated
	// into an apparently valid WireGuard packet (or a binding probe).
	buffer := make([]byte, 65535)
	for {
		n, source, err := p.udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		r.mu.Lock()
		if _, alive := r.all[p]; !alive {
			r.mu.Unlock()
			return
		}
		if !p.bound {
			r.probeLocked(p, buffer[:n], source)
			r.mu.Unlock()
			continue
		}
		if p.pending != nil && r.probeLocked(p.pending, buffer[:n], source) {
			r.mu.Unlock()
			continue
		}
		if n == 0 || n > r.cfg.MaxDatagramBytes || !sameUDPAddr(source, p.endpoint) {
			r.mu.Unlock()
			continue
		}
		p.lastSeen = time.Now()
		target := r.peers[v2PeerKey{p.key.session, p.destination}]
		if target != nil && target.destination == p.key.device {
			_ = target.udp.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := target.udp.WriteToUDP(buffer[:n], target.endpoint); err == nil {
				target.lastSeen = time.Now()
			}
		}
		r.mu.Unlock()
	}
}

func (r *UDPPairV2) probeLocked(p *v2Peer, data []byte, source *net.UDPAddr) bool {
	if string(data) != "HHU2P"+p.nonce {
		return false
	}
	if time.Now().Before(p.deadline) && p.probes < 4 &&
		(p.candidate == nil || sameUDPAddr(p.candidate, source)) {
		p.candidate = cloneUDPAddr(source)
		p.probes++
		_ = p.udp.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = p.udp.WriteToUDP([]byte("HHU2C"+p.challenge), source)
	}
	return true
}

func (r *UDPPairV2) removeLocked(p *v2Peer) {
	delete(r.all, p)
	if r.peers[p.key] == p {
		delete(r.peers, p.key)
	}
	if p.probeParent != nil {
		if p.probeParent.pending == p {
			p.probeParent.pending = nil
		}
		return // Only the established parent owns the borrowed socket.
	}
	if p.pending != nil {
		r.removeLocked(p.pending)
	}
	_ = p.udp.Close()
}

func (r *UDPPairV2) pruneLocked(now time.Time) {
	for p := range r.all {
		if (!p.bound && !now.Before(p.deadline)) ||
			(p.bound && now.Sub(p.lastSeen) >= r.cfg.IdleTimeout) {
			r.removeLocked(p)
		}
	}
	ticketNow := now
	if r.tickets.Now != nil {
		ticketNow = r.tickets.Now()
	}
	for hash, expiry := range r.used {
		if ticketNow.Unix() >= expiry {
			delete(r.used, hash)
		}
	}
}

func (r *UDPPairV2) expire() {
	defer r.wg.Done()
	interval := min(r.cfg.BindTimeout/4, r.cfg.IdleTimeout/4, time.Second)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case now := <-ticker.C:
			r.mu.Lock()
			r.pruneLocked(now)
			r.mu.Unlock()
		}
	}
}
