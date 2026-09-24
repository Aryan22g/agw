package recorder

import (
	"strings"
	"time"

	gwaudit "github.com/Aryan22g/agw/pkg/evidence"
)

// EventAgentActivity is the evidence event name for an observed span.
//
// Deliberately distinct from the confine.* and gateway.* events: a reader of
// the chain must be able to tell an observation the agent reported from a
// decision we enforced. Conflating them would let a compromised agent's own
// telemetry sit in the log looking like something we verified.
const EventAgentActivity = "recorder.agent.activity"

// Observation is one span, reduced to the fields an evidence record needs.
type Observation struct {
	AgentID  string
	TenantID string

	Action   string
	Resource string

	// Target is a network destination, and only ever that. Anything that is
	// not somewhere the agent connected belongs in another field, or shadow
	// evaluation will treat it as a hostname.
	Target string

	// Provider is the model vendor for a GenAI span. Recorded, never
	// evaluated as a destination.
	Provider string

	Outcome string
	Reason  string

	TraceID string
	SpanID  string

	StartedAt  time.Time
	FinishedAt time.Time
}

// mapSpan reduces a span to an Observation.
//
// The attribute keys below are OpenTelemetry semantic conventions, listed
// newest first within each group. Agent frameworks are moving quickly and
// emit several generations at once; accepting all of them is what makes this
// work against a pipeline that already exists rather than one built for us.
func mapSpan(span otlpSpan, resource map[string]string) Observation {
	attrs := attrMap(span.Attributes)

	// Agent identity. service.name is what almost every pipeline sets.
	agent := firstOf(attrs,
		"gen_ai.agent.id", "gen_ai.agent.name", "agent.id", "agent.name")
	if agent == "" {
		agent = firstOf(resource,
			"gen_ai.agent.id", "gen_ai.agent.name", "agent.id", "agent.name", "service.name")
	}
	if agent == "" {
		// An observation nobody can attribute is close to useless, but
		// dropping it silently would be worse: it would make a gap in the
		// evidence look like an absence of activity.
		agent = "unattributed"
	}

	tenant := firstOf(attrs, "tenant.id", "gen_ai.tenant.id")
	if tenant == "" {
		tenant = firstOf(resource, "tenant.id", "gen_ai.tenant.id", "service.namespace")
	}
	if tenant == "" {
		tenant = "local"
	}

	obs := Observation{
		AgentID:    agent,
		TenantID:   tenant,
		TraceID:    decodeID(span.TraceID),
		SpanID:     decodeID(span.SpanID),
		StartedAt:  unixNano(span.StartTimeUnixNano),
		FinishedAt: unixNano(span.EndTimeUnixNano),
	}

	// What was done, and to what. Tool calls and outbound HTTP are the spans
	// that matter -- they are the ones where the agent touched something
	// outside itself.
	switch {
	case firstOf(attrs, "gen_ai.tool.name") != "":
		obs.Action = "tool." + firstOf(attrs, "gen_ai.tool.name")
		obs.Resource = firstOf(attrs, "gen_ai.tool.call.id", "gen_ai.tool.type")

	case firstOf(attrs, "http.request.method", "http.method") != "":
		obs.Action = "http." + strings.ToLower(firstOf(attrs, "http.request.method", "http.method"))
		obs.Resource = firstOf(attrs, "url.full", "http.url", "url.path", "http.target")
		obs.Target = firstOf(attrs, "server.address", "net.peer.name", "http.host")

	case firstOf(attrs, "db.system", "db.system.name") != "":
		obs.Action = "db." + firstOf(attrs, "db.operation.name", "db.operation")
		obs.Resource = firstOf(attrs, "db.namespace", "db.name", "db.collection.name")
		obs.Target = firstOf(attrs, "server.address", "net.peer.name")

	case firstOf(attrs, "gen_ai.operation.name") != "":
		obs.Action = "gen_ai." + firstOf(attrs, "gen_ai.operation.name")
		obs.Resource = firstOf(attrs, "gen_ai.request.model", "gen_ai.response.model")
		// Provider deliberately does NOT go in Target.
		//
		// gen_ai.system is a provider name ("anthropic", "openai"), not a
		// network destination. Putting it in Target made shadow mode evaluate
		// it as a hostname against the egress allowlist and report a confident
		// "would deny" for an ordinary model call. One bogus denial in a
		// report costs the whole report its credibility, so an observation
		// with no real destination is left with none and comes back
		// not_evaluable.
		obs.Provider = firstOf(attrs, "gen_ai.system", "gen_ai.provider.name")

	default:
		obs.Action = span.Name
	}

	if obs.Action == "" {
		obs.Action = span.Name
	}
	if obs.Resource == "" {
		obs.Resource = obs.Target
	}
	if obs.Resource == "" {
		obs.Resource = obs.Provider
	}

	// OTLP status: 0 unset, 1 ok, 2 error.
	switch span.Status.Code {
	case 2:
		obs.Outcome = "error"
		obs.Reason = span.Status.Message
		if obs.Reason == "" {
			obs.Reason = "span_status_error"
		}
	case 1:
		obs.Outcome = "allow"
		obs.Reason = "observed"
	default:
		obs.Outcome = "allow"
		obs.Reason = "observed"
	}

	return obs
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// toEvent renders an Observation as an evidence record.
//
// RouteID carries a marker rather than a route: a reader must be able to tell
// self-reported activity from an enforced decision without consulting
// anything else, because the trustworthiness of the two is not the same.
func (o Observation) toEvent() gwaudit.GatewayEvent {
	ev := gwaudit.GatewayEvent{
		TenantID:     o.TenantID,
		AgentID:      o.AgentID,
		Action:       o.Action,
		ResourceType: "observed",
		ResourceID:   o.Resource,
		BackendID:    firstNonEmpty(o.Target, o.Provider),
		RouteID:      "self-reported",
		Producer:     gwaudit.ProducerRecorder,
		Decision:     o.Outcome,
		ReasonCode:   o.Reason,
		TraceID:      o.TraceID,
		RequestID:    o.SpanID,
		StartedAt:    o.StartedAt,
		FinishedAt:   o.FinishedAt,
	}
	if !o.StartedAt.IsZero() && !o.FinishedAt.IsZero() {
		ev.LatencyMS = o.FinishedAt.Sub(o.StartedAt).Milliseconds()
	}
	return ev
}
