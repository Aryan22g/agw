package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	gwaudit "github.com/Aryan22g/agw/internal/gateway/audit"
	"github.com/Aryan22g/agw/internal/gateway/authz"
	"github.com/Aryan22g/agw/internal/gateway/routing"
)

// Sink records decisions.
type Sink interface {
	Write(ctx context.Context, eventName string, ev gwaudit.GatewayEvent) (gwaudit.Record, error)
}

// Config configures the MCP enforcement point.
type Config struct {
	// Upstream is the MCP server this proxy fronts.
	Upstream *url.URL

	// Authorizer decides tool calls. The same engine the gateway uses, so a
	// tenant writes one policy rather than one per enforcement point.
	Authorizer authz.Engine

	Sink   Sink
	Logger *slog.Logger

	// TenantID and AgentID identify the caller.
	//
	// Taken from configuration rather than from the request, because MCP has
	// no identity of its own that we could trust. At Level 2 the agent is
	// cooperating by configuration; Level 3 is where identity stops being
	// something the caller asserts.
	TenantID string
	AgentID  string

	// DefaultRiskClass is applied to tool calls.
	//
	// Defaults to destructive, which is deliberate: nothing in MCP says what
	// a tool does, and assuming a tool named "search" only reads is how a
	// policy that looks careful turns out not to be. An operator who knows
	// better lowers it per deployment.
	DefaultRiskClass routing.RiskClass

	// RiskByTool overrides the default for named tools.
	RiskByTool map[string]routing.RiskClass

	MaxBodyBytes int64

	// PinTools refuses every tool call once the server has changed the
	// tools it advertises. Off by default, like every enforcement feature:
	// servers that legitimately add tools mid-session exist, and an operator
	// should see the change reported before choosing to block on it.
	PinTools bool
}

func (c *Config) validate(needUpstream bool) error {
	if needUpstream && c.Upstream == nil {
		return errors.New("mcp: an upstream is required")
	}
	if c.Authorizer == nil {
		return errors.New("mcp: an authorizer is required")
	}
	if c.Sink == nil {
		return errors.New("mcp: an evidence sink is required")
	}
	if c.TenantID == "" || c.AgentID == "" {
		return errors.New("mcp: tenant and agent id are required")
	}
	return nil
}

func (c *Config) defaults() {
	if c.DefaultRiskClass == "" {
		c.DefaultRiskClass = routing.RiskDestructive
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 4 << 20
	}
}

// Proxy enforces policy on MCP traffic over HTTP.
type Proxy struct {
	*Enforcer
	reverse *httputil.ReverseProxy
}

// New builds an MCP enforcement point in front of an HTTP server.
func New(cfg Config) (*Proxy, error) {
	if err := cfg.validate(true); err != nil {
		return nil, err
	}
	cfg.defaults()
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	rp := httputil.NewSingleHostReverseProxy(cfg.Upstream)
	rp.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelWarn)

	return &Proxy{Enforcer: newEnforcer(cfg, log, cfg.Upstream.String()), reverse: rp}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		p.reverse.ServeHTTP(w, r)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.cfg.MaxBodyBytes))
	if err != nil {
		p.writeReply(w, p.errorReply(nil, false, nil, CodeUnavailable, "request body could not be read", nil))
		return
	}

	v := p.Admit(r.Context(), body)
	if !v.Forward {
		p.writeReply(w, v.Reply)
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	// tools/list replies are inspected on the way back so a server changing
	// what it advertises becomes an evidence record.
	if requests, _, err := ParseBatch(body); err == nil {
		for _, req := range requests {
			if req.Method == MethodToolsList {
				p.serveWithInventory(w, r)
				return
			}
		}
	}
	p.reverse.ServeHTTP(w, r)
}

// writeReply answers with HTTP 200 and a JSON-RPC error, not an HTTP error
// status: a refusal is a protocol-level answer the model should see, while an
// HTTP error reads as a transport failure worth retrying.
func (p *Proxy) writeReply(w http.ResponseWriter, reply []byte) {
	if reply == nil {
		w.WriteHeader(http.StatusAccepted) // a refused notification has no response
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(reply, '\n'))
}

// serveWithInventory forwards the request and inspects the reply for a
// tools/list result, so a server that changes what it advertises leaves a
// record rather than doing it silently.
func (p *Proxy) serveWithInventory(w http.ResponseWriter, r *http.Request) {
	capture := &captureWriter{ResponseWriter: w, limit: p.cfg.MaxBodyBytes}
	p.reverse.ServeHTTP(capture, r)
	p.ObserveResponse(r.Context(), capture.body.Bytes(), true)
}

// captureWriter tees the upstream response so it can be inspected without
// changing what the client receives.
type captureWriter struct {
	http.ResponseWriter
	body  bytes.Buffer
	limit int64
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if int64(c.body.Len()) < c.limit {
		c.body.Write(b)
	}
	return c.ResponseWriter.Write(b)
}
