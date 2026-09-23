package mcp

// Evidence event names for MCP enforcement.
const (
	// EventToolAllowed is written before the call is forwarded.
	EventToolAllowed = "mcp.tool.allowed"

	// EventToolDenied covers a refused tool call or resource read.
	EventToolDenied = "mcp.tool.denied"

	// EventMethodObserved records a method that carries no authority --
	// initialize, ping, tools/list -- so the chain shows the whole
	// conversation rather than only its enforced parts.
	EventMethodObserved = "mcp.method.observed"

	// EventToolsAdvertised records the set of tools a server offered.
	EventToolsAdvertised = "mcp.tools.advertised"

	// EventToolsChanged is written when a server advertises a different set
	// of tools than it did before.
	//
	// This is the highest-severity event this package produces. A server
	// redefining a tool after being approved is the rug pull the MCP threat
	// literature keeps returning to, and nothing in the protocol surfaces it.
	EventToolsChanged = "mcp.tools.changed"
)
