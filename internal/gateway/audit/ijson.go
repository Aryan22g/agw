package audit

import (
	"encoding/json"

	"github.com/Aryan22g/agw/internal/strictjson"
)

// checkIJSON rejects a line that repeats a member name in any object. See
// internal/strictjson for why, and RFC-0009 §1.
func checkIJSON(raw []byte) error { return strictjson.NoDuplicates(raw) }

// eventMemberNames are the JSON member names of GatewayEvent. A test pins
// this list to the struct by reflection, so a field added there cannot be
// missed here.
var eventMemberNames = []string{
	"EventID", "TenantID", "AgentID", "KeyID", "DecisionID", "RequestID", "TraceID",
	"SourceTenant", "Federated", "TrustGrant", "RouteID", "Action", "ResourceType",
	"ResourceID", "BackendID", "Risk", "Producer", "Decision", "ReasonCode",
	"HTTPStatus", "SourceIP", "UserAgent", "StartedAt", "FinishedAt", "LatencyMS",
}

// checkExactNames rejects member names that equal a defined name except for
// case. encoding/json matches names case-insensitively, which let a verified
// record display a different decision from the one that was signed; see
// internal/strictjson.
func checkExactNames(obj map[string]json.RawMessage, defined []string) error {
	return strictjson.ExactNames(obj, defined...)
}
