package confine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	gwaudit "github.com/Aryan22g/agw/pkg/evidence"
)

// Sink records egress decisions. Satisfied by *audit.EvidenceSink, so the
// confinement plane writes into the same tamper-evident chain as the gateway.
type Sink interface {
	Write(ctx context.Context, eventName string, ev gwaudit.GatewayEvent) (gwaudit.Record, error)
}

// ProxyConfig configures the confinement proxy.
type ProxyConfig struct {
	Policy   *Policy
	Registry *Registry
	Resolver *Resolver
	Sink     Sink
	Logger   *slog.Logger

	// IdleTimeout bounds how long a tunnelled connection may sit idle.
	IdleTimeout time.Duration

	// FailOpenOnAuditError allows egress when the decision could not be
	// recorded. It defaults to false and should stay false: an action that
	// reaches the network but never reaches the evidence log is exactly the
	// gap this exists to close.
	FailOpenOnAuditError bool
}

// Proxy is the enforcement point. Every packet a confined workload sends
// outward arrives here, because the workload has no other route -- that is
// established by the network, outside anything the workload controls, not by
// the workload choosing to use a proxy.
type Proxy struct {
	cfg ProxyConfig
	log *slog.Logger

	allowed atomic.Uint64
	denied  atomic.Uint64
}

// NewProxy builds a Proxy. Every security-relevant dependency is required:
// a nil policy or registry would mean silently skipping a check rather than
// refusing to start.
func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	if cfg.Policy == nil {
		return nil, errors.New("confine: policy is required")
	}
	if cfg.Registry == nil {
		return nil, errors.New("confine: registry is required")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("confine: resolver is required")
	}
	if cfg.Sink == nil {
		return nil, errors.New("confine: evidence sink is required")
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	return &Proxy{cfg: cfg, log: log}, nil
}

// Stats reports allow/deny counts.
func (p *Proxy) Stats() (allowed, denied uint64) {
	return p.allowed.Load(), p.denied.Load()
}

// decision accumulates what is known about one egress attempt, so a record can
// be written from any exit point with whatever has been established so far.
type decision struct {
	start      time.Time
	decisionID string

	action   string
	workload Identity
	known    bool

	sourceIP string
	host     string
	port     int
	dialed   string
	note     string
}

// ServeHTTP handles both CONNECT tunnels and plain HTTP forward requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d := &decision{
		start:      time.Now().UTC(),
		decisionID: newDecisionID(),
		sourceIP:   hostOf(r.RemoteAddr),
	}

	if r.Method == http.MethodConnect {
		d.action = ActionConnect
		p.handleConnect(w, r, d)
		return
	}
	d.action = ActionHTTP
	p.handleHTTP(w, r, d)
}

// resolvePeer establishes who is calling, from the address the connection
// arrived on. Nothing the caller sends is consulted -- there is no header, no
// token and no credential involved, which is what makes this unforgeable from
// inside a compromised sandbox.
func (p *Proxy) resolvePeer(d *decision) (Identity, error) {
	addr, err := netip.ParseAddr(d.sourceIP)
	if err != nil {
		return Identity{}, fmt.Errorf("confine: unparseable source address %q", d.sourceIP)
	}

	ident, lookupErr := p.cfg.Registry.Lookup(addr)
	if lookupErr != nil {
		return ident, lookupErr
	}
	d.workload = ident
	d.known = true
	return ident, nil
}

// authorize runs the full decision: identity, policy, then the structural
// guard. Returns the validated destination addresses on success.
func (p *Proxy) authorize(ctx context.Context, d *decision, authority string, defaultPort int) ([]netip.Addr, string, error) {
	// The destination is parsed FIRST, before identity and before policy, so
	// that every refusal record says what was being attempted. A denial that
	// reads "unknown workload, destination unknown" tells an incident
	// responder nothing; the same denial naming the metadata endpoint tells
	// them what they are dealing with. The gateway orders route matching
	// before authentication for exactly this reason.
	host, port, err := SplitHostPort(authority, defaultPort)
	if err != nil {
		return nil, "malformed_destination", err
	}
	d.host, d.port = host, port

	// A destination given as an IP literal is classified before policy runs.
	//
	// Policy-first would be safe -- an unlisted address is refused either way
	// -- but it would record the refusal as an ordinary allowlist miss, making
	// an agent probing 169.254.169.254 for cloud credentials indistinguishable
	// from an agent with a typo in a hostname. Those are not the same event,
	// and the evidence has to be able to tell them apart.
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		if err := p.cfg.Resolver.guard.Check(literal); err != nil {
			// Identity is resolved even on this path so the probe is
			// attributed to a workload rather than just an address.
			_, _ = p.resolvePeer(d)
			return nil, Reason(err), err
		}
	}

	if _, err := p.resolvePeer(d); err != nil {
		return nil, reasonForIdentityError(err), err
	}

	note, err := p.cfg.Policy.Permits(d.workload.WorkloadID, host, port)
	if err != nil {
		return nil, Reason(ErrNotPermitted), err
	}
	d.note = note

	// The guard runs AFTER policy and cannot be satisfied by it. A permitted
	// hostname that resolves into refused address space is refused: policy
	// says where the workload may go, the guard says what may be reached at
	// all, and the second is not a subset of the first.
	addrs, err := p.cfg.Resolver.Resolve(ctx, host)
	if err != nil {
		return nil, Reason(err), err
	}
	d.dialed = addrs[0].String()

	return addrs, "allowed", nil
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request, d *decision) {
	ctx := r.Context()

	addrs, reason, err := p.authorize(ctx, d, r.Host, 443)
	if err != nil {
		p.refuse(w, r, d, reason, err, http.StatusForbidden)
		return
	}

	// Record the allow before connecting. If the record cannot be written the
	// connection does not happen -- same discipline as the gateway's forward
	// path, for the same reason.
	if err := p.record(ctx, EventEgressAllowed, d, "allow", "allowed", http.StatusOK); err != nil {
		if !p.cfg.FailOpenOnAuditError {
			p.refuse(w, r, d, "dependency_unavailable", err, http.StatusServiceUnavailable)
			return
		}
		p.log.Warn("permitting unrecorded egress because FailOpenOnAuditError is set",
			slog.String("decision_id", d.decisionID))
	}

	upstream, err := p.dialValidated(ctx, addrs, d.port)
	if err != nil {
		p.refuse(w, r, d, "destination_unreachable", err, http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		p.refuse(w, r, d, "internal_error", errors.New("connection cannot be hijacked"),
			http.StatusInternalServerError)
		return
	}

	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		p.log.Error("hijack failed", slog.Any("error", err))
		return
	}

	// Track both ends so the kill switch can close them. If the workload was
	// revoked between the policy check and here, Track refuses and we tear
	// down immediately rather than establishing a tunnel for a dead workload.
	releaseClient, err := p.cfg.Registry.Track(d.workload.WorkloadID, client)
	if err != nil {
		_ = client.Close()
		_ = upstream.Close()
		p.countDenied()
		_ = p.record(ctx, EventEgressDenied, d, "deny", Reason(ErrRevoked), http.StatusForbidden)
		return
	}
	releaseUpstream, err := p.cfg.Registry.Track(d.workload.WorkloadID, upstream)
	if err != nil {
		releaseClient()
		_ = client.Close()
		_ = upstream.Close()
		p.countDenied()
		return
	}

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		releaseClient()
		releaseUpstream()
		_ = client.Close()
		_ = upstream.Close()
		return
	}

	p.countAllowed()

	go func() {
		defer releaseClient()
		defer releaseUpstream()
		sent, received := pipe(client, upstream, p.cfg.IdleTimeout)

		ev := p.event(d, "allow", "closed", http.StatusOK)
		ev.LatencyMS = time.Since(d.start).Milliseconds()
		// Byte counts ride in the user-agent-free fields rather than adding
		// columns to the shared event shape.
		ev.UserAgent = fmt.Sprintf("bytes_out=%d bytes_in=%d", sent, received)
		_, _ = p.cfg.Sink.Write(context.Background(), EventEgressClosed, ev)
	}()
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, d *decision) {
	ctx := r.Context()

	if r.URL == nil || r.URL.Host == "" {
		p.refuse(w, r, d, "malformed_destination",
			errors.New("forward-proxy request without an absolute URI"), http.StatusBadRequest)
		return
	}

	addrs, reason, err := p.authorize(ctx, d, r.URL.Host, 80)
	if err != nil {
		p.refuse(w, r, d, reason, err, http.StatusForbidden)
		return
	}

	if err := p.record(ctx, EventEgressAllowed, d, "allow", "allowed", http.StatusOK); err != nil {
		if !p.cfg.FailOpenOnAuditError {
			p.refuse(w, r, d, "dependency_unavailable", err, http.StatusServiceUnavailable)
			return
		}
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return p.dialValidated(ctx, addrs, d.port)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	defer transport.CloseIdleConnections()

	outbound := r.Clone(ctx)
	outbound.RequestURI = ""
	stripHopByHop(outbound.Header)

	// Keep the Host header equal to the destination that was authorized.
	//
	// This is belt and braces, not a fix for a live bypass, and the
	// distinction is worth recording honestly. The concern was that Go sends
	// Request.Host in preference to URL.Host, so an agent naming one host in
	// the absolute URI and another in the Host header could be authorized for
	// one virtual host and served by another where the two share an IP.
	//
	// Go's server already prevents it: for an absolute-form request URI --
	// which is what a forward proxy always receives -- net/http sets
	// req.Host from req.URL.Host and discards the Host header, so the two
	// cannot diverge by the time this runs. Verified empirically rather than
	// assumed.
	//
	// The assignment stays because it costs nothing and makes the invariant
	// explicit rather than inherited from another package's parsing
	// behaviour, which is the kind of thing that changes quietly.
	outbound.Host = outbound.URL.Host

	resp, err := transport.RoundTrip(outbound)
	if err != nil {
		p.refuse(w, r, d, "destination_unreachable", err, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.countAllowed()

	stripHopByHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// dialValidated connects to one of the addresses the guard already approved.
// It never takes a hostname, so no second resolution can happen here.
func (p *Proxy) dialValidated(ctx context.Context, addrs []netip.Addr, port int) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	var lastErr error
	for _, a := range addrs {
		ap := netip.AddrPortFrom(a, uint16(port))
		conn, err := dialer.DialContext(ctx, tcpNetwork(a), ap.String())
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("confine: no reachable address: %w", lastErr)
}

// refuse denies an egress attempt, records it, and answers the caller.
func (p *Proxy) refuse(w http.ResponseWriter, r *http.Request, d *decision, reason string, cause error, status int) {
	p.countDenied()

	event := EventEgressDenied
	if errors.Is(cause, ErrUnknownWorkload) {
		event = EventUnknownSource
	}
	_ = p.record(r.Context(), event, d, "deny", reason, status)

	p.log.Warn("egress denied",
		slog.String("decision_id", d.decisionID),
		slog.String("workload", d.workload.WorkloadID),
		slog.String("source_ip", d.sourceIP),
		slog.String("destination", fmt.Sprintf("%s:%d", d.host, d.port)),
		slog.String("reason", reason),
		slog.Any("error", cause),
	)

	// The caller is told it was refused and given the decision id, but not
	// why in any detail: a confined agent enumerating the policy by reading
	// refusal reasons is doing reconnaissance we do not need to assist.
	w.Header().Set("X-AGW-Decision-Id", d.decisionID)
	w.Header().Set("X-AGW-Reason", reason)
	http.Error(w, "egress denied by policy", status)
}

func (p *Proxy) record(ctx context.Context, event string, d *decision, outcome, reason string, status int) error {
	_, err := p.cfg.Sink.Write(ctx, event, p.event(d, outcome, reason, status))
	if err != nil {
		p.log.Error("evidence write failed",
			slog.String("decision_id", d.decisionID), slog.Any("error", err))
	}
	return err
}

func (p *Proxy) event(d *decision, outcome, reason string, status int) gwaudit.GatewayEvent {
	dest := d.host
	if d.port != 0 {
		dest = fmt.Sprintf("%s:%d", d.host, d.port)
	}

	return gwaudit.GatewayEvent{
		TenantID:     d.workload.TenantID,
		AgentID:      d.workload.WorkloadID,
		KeyID:        d.workload.ImageDigest,
		DecisionID:   d.decisionID,
		Action:       d.action,
		ResourceType: "host",
		ResourceID:   dest,
		BackendID:    d.dialed,
		RouteID:      d.note,
		Decision:     outcome,
		ReasonCode:   reason,
		HTTPStatus:   status,
		SourceIP:     d.sourceIP,
		Producer:     gwaudit.ProducerConfineProxy,
		StartedAt:    d.start,
		FinishedAt:   time.Now().UTC(),
		LatencyMS:    time.Since(d.start).Milliseconds(),
	}
}

func (p *Proxy) countAllowed() { p.allowed.Add(1) }
func (p *Proxy) countDenied()  { p.denied.Add(1) }

func reasonForIdentityError(err error) string {
	switch {
	case errors.Is(err, ErrRevoked):
		return "workload_revoked"
	case errors.Is(err, ErrUnknownWorkload):
		return "unknown_workload"
	default:
		return "identity_error"
	}
}

// pipe copies in both directions until either side closes, returning the byte
// counts. Both directions are torn down when the first finishes, so a
// half-closed peer cannot strand a goroutine.
func pipe(client, upstream net.Conn, idle time.Duration) (sent, received int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = upstream.SetDeadline(time.Now().Add(idle))
		sent, _ = io.Copy(upstream, client)
		_ = upstream.Close()
		_ = client.Close()
	}()

	go func() {
		defer wg.Done()
		_ = client.SetDeadline(time.Now().Add(idle))
		received, _ = io.Copy(client, upstream)
		_ = client.Close()
		_ = upstream.Close()
	}()

	wg.Wait()
	return sent, received
}

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, k := range hopByHop {
		h.Del(k)
	}
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func newDecisionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("dec_%d", time.Now().UnixNano())
	}
	return "dec_" + hex.EncodeToString(b[:])
}
