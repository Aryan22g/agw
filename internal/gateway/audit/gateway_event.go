package audit

import "time"

const (
	EventGatewayRequestDenied         = "gateway.request.denied"
	EventGatewayRequestAllowed        = "gateway.request.allowed"
	EventGatewayRequestForwarded      = "gateway.request.forwarded"
	EventGatewayBackendFailed         = "gateway.backend.failed"
	EventGatewayRateLimited           = "gateway.rate_limited"
	EventGatewayHeaderSpoofAttempt    = "gateway.header_spoof_attempt"
	EventGatewayRouteUnknown          = "gateway.route_unknown"
	EventGatewayDependencyUnavailable = "gateway.dependency_unavailable"
)

// GatewayEvent is the enforcement-level audit record emitted by the gateway.
// It is intentionally focused on identity, routing, policy, and outcome data.
type GatewayEvent struct {
	EventID    string
	TenantID   string
	AgentID    string
	KeyID      string
	DecisionID string
	RequestID  string
	TraceID    string

	// SourceTenant is the issuing organization for a federated request, empty
	// for a local one. A federated audit trail that records only which agent
	// acted cannot answer the question federation actually raises: whose
	// agent, from which organization, under which trust relationship.
	SourceTenant string
	Federated    bool
	TrustGrant   string

	RouteID      string
	Action       string
	ResourceType string
	ResourceID   string
	BackendID    string

	// Risk is the route's risk class for this decision.
	Risk string

	// Producer names what wrote this record: an enforcement point, or a
	// recorder taking the agent's word for it.
	//
	// A signed checkpoint authenticates every record chained beneath it, so
	// one producer's chain is already attributable as a whole. This field
	// exists for the case where several producers share a chain, and for the
	// distinction that actually matters to a reader: whether a record was
	// ENFORCED or merely OBSERVED. Without it, that difference lives in
	// whatever convention the producer happened to use.
	Producer string

	Decision   string
	ReasonCode string
	HTTPStatus int

	SourceIP  string
	UserAgent string

	StartedAt  time.Time
	FinishedAt time.Time
	LatencyMS  int64
}

// WithTiming populates FinishedAt and LatencyMS from a start time.
func (e GatewayEvent) WithTiming(start time.Time, finish time.Time) GatewayEvent {
	e.StartedAt = start
	e.FinishedAt = finish
	e.LatencyMS = finish.Sub(start).Milliseconds()
	return e
}

// RiskClass returns the route risk recorded for this decision.
//
// Stored inside the resource type rather than as its own column in earlier
// versions; this accessor keeps consumers stable if that changes again.
func (e GatewayEvent) RiskClass() string { return e.Risk }
