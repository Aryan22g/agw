package confine

// Evidence event names for egress decisions.
//
// These share the chain with the gateway's own events, so one evidence file
// answers both "what did this agent ask a backend to do" and "what did it try
// to reach". Keeping them in one chain is deliberate: two logs that have to be
// correlated by timestamp are two logs an incident responder has to trust
// separately.
const (
	// EventEgressAllowed is written BEFORE the connection is made. An egress
	// that happens without a record would break the central claim, so the
	// record is the thing that gates the connection rather than a report of it.
	EventEgressAllowed = "confine.egress.allowed"

	// EventEgressDenied covers every refusal: policy, guard, and revocation.
	// These are the highest-signal records in the system -- an agent probing
	// the metadata endpoint appears here and nowhere else.
	EventEgressDenied = "confine.egress.denied"

	// EventEgressClosed records the end of an allowed connection, with bytes
	// moved in each direction.
	EventEgressClosed = "confine.egress.closed"

	// EventWorkloadRegistered records a supervisor attesting a workload.
	EventWorkloadRegistered = "confine.workload.registered"

	// EventWorkloadRevoked records the kill switch firing, with the measured
	// teardown latency.
	EventWorkloadRevoked = "confine.workload.revoked"

	// EventEgressRefusedAtFirewall records packets the firewall dropped
	// before they ever reached the proxy.
	//
	// These are the attempts a workload made without going through us at all.
	// A probe of the cloud metadata endpoint appears here and nowhere else,
	// and it is a stronger signal than the same destination asked for through
	// the proxy: the workload chose not to ask.
	EventEgressRefusedAtFirewall = "confine.egress.refused_at_firewall"

	// EventUnknownSource records traffic from an address no supervisor
	// registered -- something is on the confined network that we did not
	// launch.
	EventUnknownSource = "confine.source.unknown"
)

// Egress actions, used as the Action field of the evidence record.
const (
	ActionConnect = "net.connect"  // CONNECT tunnel, destination-only policy
	ActionHTTP    = "http.request" // plain HTTP through the forward proxy
)
