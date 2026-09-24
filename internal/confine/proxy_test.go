package confine

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gwaudit "github.com/Aryan22g/agw/pkg/evidence"
)

type testSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (s *testSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s *testSigner) KeyID() string                   { return "test-checkpoint-key" }

// failingSink refuses every write, to exercise the fail-closed path.
type failingSink struct{}

func (failingSink) Write(context.Context, string, gwaudit.GatewayEvent) (gwaudit.Record, error) {
	return gwaudit.Record{}, errors.New("evidence sink is down")
}

type harness struct {
	proxy    *Proxy
	proxySrv *httptest.Server
	registry *Registry
	sink     *gwaudit.EvidenceSink
	logPath  string
	pub      ed25519.PublicKey
	echoAddr string
	echoPort int
}

// newHarness stands up an echo destination, an evidence chain on disk, and the
// proxy, with one workload registered as 127.0.0.1.
func newHarness(t *testing.T, opts ...func(*ProxyConfig)) *harness {
	t.Helper()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "evidence.jsonl")
	sink, err := gwaudit.NewEvidenceSink(gwaudit.EvidenceSinkConfig{
		Path:            logPath,
		Signer:          &testSigner{priv: priv, pub: pub},
		KeyID:           "test-checkpoint-key",
		CheckpointEvery: 5,
	})
	if err != nil {
		t.Fatalf("evidence sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// The echo destination is on loopback, which the guard refuses by design.
	// Tests exempt exactly that one address -- the same narrow escape an
	// operator would use for one internal service, and nothing wider.
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	policyBody := fmt.Sprintf(`
version: "1"
permit_private: ["127.0.0.1/32"]
workloads:
  - id: agent-eval-01
    allow:
      - host: "127.0.0.1"
        ports: [%d]
        note: test echo destination
`, echoPort)
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	policy, err := LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	guard, err := NewGuard(policy.PermitPrivate)
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	resolver, err := NewResolver(ResolverConfig{Guard: guard})
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}

	registry := NewRegistry()
	if err := registry.Register(Identity{
		WorkloadID:  "agent-eval-01",
		TenantID:    "tenant-alpha",
		SourceAddr:  netip.MustParseAddr("127.0.0.1"),
		ImageDigest: "sha256:abc123",
		Command:     "python harness.py",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	cfg := ProxyConfig{
		Policy:   policy,
		Registry: registry,
		Resolver: resolver,
		Sink:     sink,
	}
	for _, o := range opts {
		o(&cfg)
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	srv := httptest.NewServer(proxy)
	t.Cleanup(srv.Close)

	return &harness{
		proxy:    proxy,
		proxySrv: srv,
		registry: registry,
		sink:     sink,
		logPath:  logPath,
		pub:      pub,
		echoAddr: fmt.Sprintf("127.0.0.1:%d", echoPort),
		echoPort: echoPort,
	}
}

// connect opens a CONNECT tunnel through the proxy and returns the raw
// connection plus the status line.
func (h *harness) connect(t *testing.T, target string) (net.Conn, string) {
	t.Helper()

	c, err := net.Dial("tcp", strings.TrimPrefix(h.proxySrv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		_ = c.Close()
		t.Fatalf("read status: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})

	return c, strings.TrimSpace(status)
}

// TestMetadataEndpointIsRefusedThroughTheProxy is the headline property: an
// agent that has root in its sandbox and asks the only route it has for the
// cloud credential endpoint is refused, and the attempt is recorded.
func TestMetadataEndpointIsRefusedThroughTheProxy(t *testing.T) {
	h := newHarness(t)

	c, status := h.connect(t, "169.254.169.254:80")
	defer c.Close()

	if !strings.Contains(status, "403") {
		t.Fatalf("metadata endpoint returned %q, want 403", status)
	}

	recs := h.records(t)
	found := false
	for _, r := range recs {
		if r.EventName == EventEgressDenied && strings.Contains(r.Event.ResourceID, "169.254.169.254") {
			found = true
			if r.Event.ReasonCode != "metadata_endpoint" {
				t.Errorf("reason = %q, want metadata_endpoint", r.Event.ReasonCode)
			}
			if r.Event.AgentID != "agent-eval-01" {
				t.Errorf("the attempt was not attributed: agent = %q", r.Event.AgentID)
			}
		}
	}
	if !found {
		t.Error("the metadata probe was refused but not recorded")
	}
}

func TestAllowedDestinationTunnelsAndEchoes(t *testing.T) {
	h := newHarness(t)

	c, status := h.connect(t, h.echoAddr)
	defer c.Close()

	if !strings.Contains(status, "200") {
		t.Fatalf("allowed destination returned %q, want 200", status)
	}

	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if strings.TrimSpace(got) != "ping" {
		t.Errorf("echo returned %q, want ping", got)
	}
}

func TestDestinationOutsideAllowlistIsRefused(t *testing.T) {
	h := newHarness(t)

	c, status := h.connect(t, "evil.example.com:443")
	defer c.Close()

	if !strings.Contains(status, "403") {
		t.Fatalf("unlisted destination returned %q, want 403", status)
	}
	h.assertRecorded(t, EventEgressDenied, "not_in_allowlist")
}

func TestAllowedHostOnWrongPortIsRefused(t *testing.T) {
	h := newHarness(t)

	c, status := h.connect(t, fmt.Sprintf("127.0.0.1:%d", h.echoPort+1))
	defer c.Close()

	if !strings.Contains(status, "403") {
		t.Fatalf("wrong port returned %q, want 403", status)
	}
}

// TestUnregisteredSourceIsRefused covers something on the confined network
// that no supervisor launched.
func TestUnregisteredSourceIsRefused(t *testing.T) {
	h := newHarness(t)

	// Re-register the only known workload onto a different address so that
	// loopback -- where the test client actually comes from -- is unknown.
	h2 := NewRegistry()
	if err := h2.Register(Identity{
		WorkloadID: "somebody-else",
		SourceAddr: netip.MustParseAddr("10.9.9.9"),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	h.proxy.cfg.Registry = h2

	c, status := h.connect(t, h.echoAddr)
	defer c.Close()

	if !strings.Contains(status, "403") {
		t.Fatalf("unregistered source returned %q, want 403", status)
	}
	h.assertRecorded(t, EventUnknownSource, "unknown_workload")
}

func TestRevokedWorkloadCannotOpenNewTunnels(t *testing.T) {
	h := newHarness(t)

	if _, err := h.registry.Revoke("agent-eval-01", "test revocation"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	c, status := h.connect(t, h.echoAddr)
	defer c.Close()

	if !strings.Contains(status, "403") {
		t.Fatalf("revoked workload returned %q, want 403", status)
	}
	h.assertRecorded(t, EventEgressDenied, "workload_revoked")
}

// TestKillSwitchClosesALiveTunnel is the control that has to work when the
// agent is actively hostile: an established connection must die, not drain.
func TestKillSwitchClosesALiveTunnel(t *testing.T) {
	h := newHarness(t)

	c, status := h.connect(t, h.echoAddr)
	defer c.Close()
	if !strings.Contains(status, "200") {
		t.Fatalf("setup tunnel returned %q", status)
	}

	// Confirm the tunnel carries traffic before we cut it.
	if _, err := c.Write([]byte("before\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("tunnel was not live: %v", err)
	}

	res, err := h.registry.Revoke("agent-eval-01", "kill switch test")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.ConnectionsClosed < 2 {
		t.Errorf("closed %d connections, expected both ends of the tunnel", res.ConnectionsClosed)
	}
	if res.Latency > 100*time.Millisecond {
		t.Errorf("kill switch took %v, want < 100ms", res.Latency)
	}
	t.Logf("tunnel killed in %v (%d connections)", res.Latency, res.ConnectionsClosed)

	// The tunnel must now be dead.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte("after\n"))
	if _, err := r.ReadString('\n'); err == nil {
		t.Error("the tunnel still carried traffic after revocation")
	}
}

// TestUnrecordableEgressIsRefused is the fail-closed discipline: if the
// decision cannot be written to the chain, the connection does not happen.
func TestUnrecordableEgressIsRefused(t *testing.T) {
	h := newHarness(t, func(c *ProxyConfig) { c.Sink = failingSink{} })

	c, status := h.connect(t, h.echoAddr)
	defer c.Close()

	if !strings.Contains(status, "503") {
		t.Fatalf("unrecordable egress returned %q, want 503", status)
	}
}

// TestEvidenceChainVerifies proves the artifact the whole product rests on:
// after a run, the log verifies with nothing but the file and a public key.
func TestEvidenceChainVerifies(t *testing.T) {
	h := newHarness(t)

	c1, _ := h.connect(t, h.echoAddr)
	c1.Close()
	c2, _ := h.connect(t, "169.254.169.254:80")
	c2.Close()
	c3, _ := h.connect(t, "evil.example.com:443")
	c3.Close()

	if err := h.sink.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}

	f, err := os.Open(h.logPath)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	result, problems, err := gwaudit.Verify(f, h.pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(problems) != 0 {
		for _, p := range problems {
			t.Errorf("verification problem: %s", p.Error())
		}
	}
	if result.Records == 0 {
		t.Fatal("the chain is empty")
	}
	t.Logf("verified %d records, %d checkpoints", result.Records, result.Checkpoints)
}

func (h *harness) records(t *testing.T) []gwaudit.Record {
	t.Helper()

	// Force everything buffered to disk before reading it back.
	if err := h.sink.Checkpoint(); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	f, err := os.Open(h.logPath)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	recs, err := gwaudit.ReadRecords(f)
	if err != nil {
		t.Fatalf("read records: %v", err)
	}
	return recs
}

func (h *harness) assertRecorded(t *testing.T, eventName, reason string) {
	t.Helper()

	for _, r := range h.records(t) {
		if r.EventName == eventName && r.Event.ReasonCode == reason {
			return
		}
	}
	t.Errorf("no %s record with reason %q was written", eventName, reason)
}

// TestHostHeaderCannotDivergeFromTheAuthorizedDestination guards an invariant
// this package depends on but does not currently enforce by itself.
//
// Policy is evaluated against the absolute URI. If the Host header could
// differ from it, an agent could be authorized for one virtual host and
// served by another where the two share an IP -- a CDN or load balancer,
// which is the common case.
//
// Today net/http makes that impossible: for an absolute-form request URI,
// which is what a forward proxy always receives, the server sets req.Host
// from req.URL.Host and discards the Host header. This test passes with or
// without the assignment in handleHTTP, and that is the honest description of
// it: it is a regression guard on someone else's parsing behaviour, not proof
// that we caught a bypass.
//
// Driven over a raw socket, because Go's own client builds a proxy request's
// absolute URI from req.Host and cannot produce the divergence at all.
func TestHostHeaderCannotDivergeFromTheAuthorizedDestination(t *testing.T) {
	seen := make(chan string, 4)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	_, backendPort, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	h := newHarnessForHTTP(t, backendPort)
	authorized := "127.0.0.1:" + backendPort

	c, err := net.Dial("tcp", strings.TrimPrefix(h.proxySrv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	// Absolute URI names the permitted destination; the Host header does not.
	raw := fmt.Sprintf(
		"GET http://%s/x HTTP/1.1\r\nHost: internal-admin.example.com\r\nConnection: close\r\n\r\n",
		authorized)
	if _, err := c.Write([]byte(raw)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.ReadAll(c)

	select {
	case got := <-seen:
		if got != authorized {
			t.Errorf("the backend saw Host %q; policy authorized %q -- an agent reached "+
				"a virtual host it was not permitted", got, authorized)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the request never reached the backend")
	}
}

// newHarnessForHTTP builds a harness whose policy permits plain HTTP to the
// given loopback port, for the forward-proxy path.
func newHarnessForHTTP(t *testing.T, port string) *harness {
	t.Helper()

	h := newHarness(t)

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	body := fmt.Sprintf(`
version: "1"
permit_private: ["127.0.0.1/32"]
workloads:
  - id: agent-eval-01
    allow:
      - host: "127.0.0.1"
        ports: [%s]
`, port)
	if err := os.WriteFile(policyPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	policy, err := LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	h.proxy.cfg.Policy = policy
	return h
}
