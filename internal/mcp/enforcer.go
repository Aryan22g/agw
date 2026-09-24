package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Aryan22g/agw/pkg/authz"
	"github.com/Aryan22g/agw/pkg/decision"
	gwaudit "github.com/Aryan22g/agw/pkg/evidence"
)

// Enforcer is the MCP policy decision and evidence core, independent of how
// messages arrive. The HTTP proxy and the stdio wrapper are both thin
// transports around it, so a tool call is judged and recorded identically
// whether the server is a URL or a subprocess.
type Enforcer struct {
	cfg       Config
	log       *slog.Logger
	inventory *Inventory
	backend   string

	allowed atomic.Uint64
	denied  atomic.Uint64
	changes atomic.Uint64

	// frozen is set when PinTools is on and the server changed what it
	// advertises. From then on no tool call is forwarded.
	frozen atomic.Bool

	// pendingLists holds the ids of tools/list requests in flight, so a
	// transport that sees responses separately from requests (stdio) can
	// tell which response to inspect.
	mu           sync.Mutex
	pendingLists map[string]bool
}

// Verdict is the enforcer's answer for one inbound message.
type Verdict struct {
	// Forward is true when the message may go to the server unchanged.
	Forward bool

	// Reply, when Forward is false, is the JSON-RPC response to send back
	// instead. Nil for a refused notification, which gets no response.
	Reply []byte
}

func newEnforcer(cfg Config, log *slog.Logger, backend string) *Enforcer {
	return &Enforcer{
		cfg: cfg, log: log, inventory: NewInventory(), backend: backend,
		pendingLists: map[string]bool{},
	}
}

// NewEnforcer builds an enforcer for a transport other than the HTTP proxy.
// backend names the server in evidence records -- a URL or a command line.
func NewEnforcer(cfg Config, backend string) (*Enforcer, error) {
	if err := cfg.validate(false); err != nil {
		return nil, err
	}
	cfg.defaults()
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return newEnforcer(cfg, log, backend), nil
}

// Stats reports allowed calls, denied calls and observed inventory changes.
func (e *Enforcer) Stats() (allowed, denied, inventoryChanges uint64) {
	return e.allowed.Load(), e.denied.Load(), e.changes.Load()
}

// Admit decides one client-to-server message, which may be a batch.
//
// Every request in a batch is decided before any is forwarded, and one
// refusal refuses the whole batch: forwarding the permitted subset would mean
// rewriting the body, and a proxy that rewrites what it forwards can be blamed
// for behaviour it did not intend.
//
// Every allowed call is recorded BEFORE it is forwarded, and if the record
// cannot be written the call is refused. An action that reaches a tool but
// never reaches the evidence is the gap this exists to close -- the same
// discipline as the gateway and the confinement proxy, which this enforcement
// point previously did not follow: record errors were logged and the call went
// through anyway.
func (e *Enforcer) Admit(ctx context.Context, body []byte) Verdict {
	requests, isBatch, err := ParseBatch(body)
	if err != nil {
		e.denied.Add(1)
		e.record(ctx, EventToolDenied, "mcp.message.malformed", truncate(err.Error(), 200),
			"deny", "malformed_request")
		return Verdict{Reply: e.errorReply(nil, false, nil, CodeInvalidRequest,
			"request refused: it could be read more than one way", nil)}
	}

	// Responses the client sends back to server-initiated requests
	// (sampling, roots, elicitation) carry no authority of the agent's and
	// are passed through. They are recognised by having no method.
	if !isBatch && requests[0].Method == "" {
		return Verdict{Forward: true}
	}

	for _, req := range requests {
		d, action, resource := e.decide(ctx, req)
		if d.Allowed() {
			continue
		}
		e.denied.Add(1)
		e.record(ctx, EventToolDenied, action, resource, "deny", string(d.Reason))
		e.log.Warn("mcp call denied",
			slog.String("agent", e.cfg.AgentID), slog.String("method", req.Method),
			slog.String("action", action), slog.String("resource", resource),
			slog.String("reason", string(d.Reason)))
		return Verdict{Reply: e.errorReply(requests, isBatch, req.ID, CodePolicyDenied, "denied by policy",
			map[string]string{"reason": string(d.Reason), "action": action})}
	}

	for _, req := range requests {
		action, resource := describe(req)
		event := EventMethodObserved
		if _, isTool := req.ToolName(); isTool {
			event = EventToolAllowed
		}
		if err := e.record(ctx, event, action, resource, "allow", "permitted"); err != nil {
			e.denied.Add(1)
			return Verdict{Reply: e.errorReply(requests, isBatch, req.ID, CodeUnavailable,
				"refused: the decision could not be recorded", map[string]string{"reason": "dependency_unavailable"})}
		}
		if event == EventToolAllowed {
			e.allowed.Add(1)
		}
		if req.Method == MethodToolsList && len(req.ID) > 0 {
			e.mu.Lock()
			e.pendingLists[string(req.ID)] = true
			e.mu.Unlock()
		}
	}
	return Verdict{Forward: true}
}

// decide authorizes one JSON-RPC request.
func (e *Enforcer) decide(ctx context.Context, req Request) (d decision.Decision, action, resource string) {
	action, resource = describe(req)

	// Methods that carry no authority are observed, not gated. Refusing
	// `initialize` would break the session before policy could say anything
	// useful about it.
	switch req.Method {
	case MethodToolsCall, MethodResourcesRead:
	default:
		return decision.Allow(), action, resource
	}

	if req.Method == MethodToolsCall && e.frozen.Load() {
		return decision.Deny(ReasonToolsChanged, nil,
			"the server changed the tools it advertises after they were first observed; "+
				"tool calls are refused until an operator reviews it and restarts"), action, resource
	}

	risk := e.cfg.DefaultRiskClass
	if name, ok := req.ToolName(); ok {
		if override, found := e.cfg.RiskByTool[name]; found {
			risk = override
		}
	}

	return e.cfg.Authorizer.Authorize(ctx, authz.Request{
		TenantID: e.cfg.TenantID, AgentID: e.cfg.AgentID,
		Action: action, Resource: resource, RiskClass: risk, Now: time.Now().UTC(),
	}), action, resource
}

// ReasonToolsChanged refuses tool calls after a pinned server redefined its
// tools.
const ReasonToolsChanged decision.Reason = "tool_inventory_changed"

// ObserveResponse inspects a server-to-client message. A tools/list result is
// hashed, and a change from what the server advertised before is recorded --
// and, with PinTools, stops further tool calls.
//
// requested says whether the caller already knows this message answers a
// tools/list (HTTP knows from its own request); otherwise the enforcer
// matches it against the tools/list ids it saw go out.
func (e *Enforcer) ObserveResponse(ctx context.Context, body []byte, requested bool) {
	if !requested {
		var probe struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(body, &probe) != nil || len(probe.ID) == 0 {
			return
		}
		e.mu.Lock()
		requested = e.pendingLists[string(probe.ID)]
		delete(e.pendingLists, string(probe.ID))
		e.mu.Unlock()
		if !requested {
			return
		}
	}

	set, changed, previous, ok := e.inventory.Observe(e.backend, body)
	if !ok {
		return
	}
	names := strings.Join(set.Names, ",")

	if changed {
		e.changes.Add(1)
		if e.cfg.PinTools {
			e.frozen.Store(true)
		}
		e.log.Warn("the MCP server changed the tools it advertises",
			slog.String("server", e.backend), slog.String("previous_digest", previous),
			slog.String("digest", set.Digest), slog.Int("tool_count", set.Count),
			slog.Bool("tool_calls_blocked", e.cfg.PinTools),
			slog.String("advice", "a server redefining tools after approval is the rug pull; "+
				"review before continuing to use it"))
		_ = e.record(ctx, EventToolsChanged, "mcp.tools.changed",
			fmt.Sprintf("was=%s now=%s tools=%s", short(previous), short(set.Digest), names),
			"deny", "tool_inventory_changed")
		return
	}

	_ = e.record(ctx, EventToolsAdvertised, "mcp.tools.advertised",
		fmt.Sprintf("digest=%s count=%d tools=%s", short(set.Digest), set.Count, names),
		"allow", "observed")
}

func (e *Enforcer) record(ctx context.Context, event, action, resource, outcome, reason string) error {
	now := time.Now().UTC()
	_, err := e.cfg.Sink.Write(ctx, event, gwaudit.GatewayEvent{
		TenantID: e.cfg.TenantID, AgentID: e.cfg.AgentID, DecisionID: newDecisionID(),
		Action: action, ResourceType: "mcp", ResourceID: resource, BackendID: e.backend,
		Decision: outcome, ReasonCode: reason, Producer: gwaudit.ProducerMCP,
		StartedAt: now, FinishedAt: now,
	})
	if err != nil {
		e.log.Error("could not record mcp decision", slog.String("event", event), slog.Any("error", err))
	}
	return err
}

// errorReply builds the JSON-RPC answer for a refused message. A refused
// notification (no id) gets no response, as JSON-RPC requires.
func (e *Enforcer) errorReply(requests []Request, isBatch bool, id json.RawMessage, code int, msg string, data any) []byte {
	var v any
	if isBatch {
		out := make([]ErrorResponse, 0, len(requests))
		for _, r := range requests {
			if len(r.ID) == 0 {
				continue
			}
			out = append(out, NewErrorResponse(r.ID, code, msg,
				map[string]string{"reason": "one or more calls in this batch were refused"}))
		}
		if len(out) == 0 {
			return nil
		}
		v = out
	} else {
		if requests != nil && len(id) == 0 {
			return nil
		}
		if id == nil {
			id = json.RawMessage("null")
		}
		v = NewErrorResponse(id, code, msg, data)
	}
	b, _ := json.Marshal(v)
	return b
}

// describe renders a request as an action and a resource for policy.
//
// Tool calls become "mcp.tool.<name>" so a policy can name them with the same
// dotted wildcards it uses for every other action -- "mcp.tool.*" covers all
// of them, "mcp.tool.delete_*" does not, because the wildcard matches on the
// dot boundary.
func describe(req Request) (action, resource string) {
	if name, ok := req.ToolName(); ok {
		return "mcp.tool." + name, name
	}
	if uri, ok := req.ResourceURI(); ok {
		return "mcp.resource.read", uri
	}
	return "mcp.method." + strings.ReplaceAll(req.Method, "/", "."), req.Method
}

func short(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func newDecisionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("dec_%d", time.Now().UnixNano())
	}
	return "dec_" + hex.EncodeToString(b[:])
}
