package audit

// Producer identifies what wrote a record, and how much weight it carries.
//
// The distinction is the one a reader most needs and can least afford to
// guess. An enforced record is a decision the system made and acted on. An
// observed record is the agent's own account of what it did, which a
// compromised agent can fabricate. Both belong in the chain; treating them
// alike would let a compromised agent's telemetry read as verified.
const (
	// ProducerConfineProxy is the egress enforcement point. The workload
	// cannot bypass it, so its records describe what actually happened.
	ProducerConfineProxy = "enforced:confine-proxy"

	// ProducerConfineFirewall is the packet filter, which records attempts
	// that never reached the proxy at all.
	ProducerConfineFirewall = "enforced:confine-firewall"

	// ProducerMCP is the MCP enforcement point.
	ProducerMCP = "enforced:mcp"

	// ProducerGateway is the inbound request pipeline.
	ProducerGateway = "enforced:gateway"

	// ProducerRecorder is telemetry the agent reported about itself. It is
	// the only producer here whose records are not evidence of enforcement,
	// and the prefix says so.
	ProducerRecorder = "observed:recorder"
)

// Enforced reports whether a record came from an enforcement point rather
// than from an agent's own telemetry.
func Enforced(producer string) bool {
	return len(producer) >= 9 && producer[:9] == "enforced:"
}
