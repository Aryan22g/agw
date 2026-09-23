// Package mcp enforces policy on Model Context Protocol tool calls.
//
// This is Level 2 of the adoption ladder: the agent still routes through us by
// configuration rather than because it has no choice, so a compromised agent
// can decline. What it buys over Level 1 is that calls are actually refused
// rather than merely counted, at the layer where an agent does the things that
// matter -- invoking tools.
//
// The 2026-07-28 MCP revision makes an interposing enforcement point a natural
// fit rather than a hack: transport is stateless, there are no long-lived
// streams to track, and authorization errors are returned per request. Read
// the NSA/CISA MCP security design CSI before changing anything here.
package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/Aryan22g/agw/internal/strictjson"
)

// JSON-RPC methods that matter for enforcement. Everything else is forwarded
// and recorded but not gated -- `initialize` and `ping` carry no authority.
const (
	MethodToolsCall     = "tools/call"
	MethodToolsList     = "tools/list"
	MethodResourcesRead = "resources/read"
	MethodResourcesList = "resources/list"
	MethodPromptsGet    = "prompts/get"
)

// JSON-RPC 2.0 reserves -32000 to -32099 for implementation-defined server
// errors. A refusal is returned in that range rather than as an HTTP status,
// because an MCP client expects a protocol-level error it can surface to the
// model, and an HTTP error would look like a transport failure worth retrying.
const (
	// CodeInvalidRequest is JSON-RPC's own code for a message that is not a
	// valid request -- used for one that two parsers would read differently.
	CodeInvalidRequest = -32600

	CodePolicyDenied = -32001
	CodeUnauthorized = -32002
	CodeUnavailable  = -32003
)

// Request is the subset of a JSON-RPC request this package reads.
//
// Params is kept raw so the body forwarded upstream is byte-identical to what
// arrived. Re-serialising it would change what the MCP server sees, and a
// proxy that quietly rewrites requests is one that can be blamed for
// behaviour it did not intend.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// ToolCallParams is the shape of a tools/call request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ResourceReadParams is the shape of a resources/read request.
type ResourceReadParams struct {
	URI string `json:"uri"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// ErrorResponse is a complete JSON-RPC error reply.
type ErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Error   Error           `json:"error"`
}

// NewErrorResponse builds a refusal that keeps the caller's id, so the client
// can match it to the request it sent.
func NewErrorResponse(id json.RawMessage, code int, message string, data any) ErrorResponse {
	return ErrorResponse{JSONRPC: "2.0", ID: id, Error: Error{Code: code, Message: message, Data: data}}
}

// ToolName extracts the tool a request invokes, if it invokes one.
func (r *Request) ToolName() (string, bool) {
	if r.Method != MethodToolsCall || len(r.Params) == 0 {
		return "", false
	}
	var p ToolCallParams
	if err := json.Unmarshal(r.Params, &p); err != nil || p.Name == "" {
		return "", false
	}
	return p.Name, true
}

// ResourceURI extracts the resource a request reads, if it reads one.
func (r *Request) ResourceURI() (string, bool) {
	if r.Method != MethodResourcesRead || len(r.Params) == 0 {
		return "", false
	}
	var p ResourceReadParams
	if err := json.Unmarshal(r.Params, &p); err != nil || p.URI == "" {
		return "", false
	}
	return p.URI, true
}

// listResponse is the part of a tools/list reply this package inspects.
type listResponse struct {
	Result struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	} `json:"result"`
}

// ParseBatch decodes a body that may be a single request or a JSON-RPC batch.
func ParseBatch(body []byte) ([]Request, bool, error) {
	trimmed := trimLeadingSpace(body)
	if len(trimmed) == 0 {
		return nil, false, fmt.Errorf("mcp: empty body")
	}

	// The enforcement point and the server must read the same message. Go
	// matches member names case-insensitively and keeps the last duplicate;
	// the JavaScript and Python servers most MCP deployments run match
	// exactly. {"method":"tools/call","Method":"initialize",...} was
	// authorized here as initialize and executed there as a tool call the
	// policy forbade. Anything two parsers could read differently is refused.
	if err := strictjson.NoDuplicates(trimmed); err != nil {
		return nil, false, fmt.Errorf("mcp: %w", err)
	}

	isBatch := trimmed[0] == '['
	var raws []json.RawMessage
	if isBatch {
		if err := json.Unmarshal(trimmed, &raws); err != nil {
			return nil, true, fmt.Errorf("mcp: malformed batch: %w", err)
		}
	} else {
		raws = []json.RawMessage{trimmed}
	}

	out := make([]Request, 0, len(raws))
	for _, raw := range raws {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, isBatch, fmt.Errorf("mcp: malformed request: %w", err)
		}
		if err := strictjson.ExactNames(obj, "jsonrpc", "id", "method", "params", "result", "error"); err != nil {
			return nil, isBatch, fmt.Errorf("mcp: %w", err)
		}
		if p, ok := obj["params"]; ok {
			var params map[string]json.RawMessage
			if json.Unmarshal(p, &params) == nil {
				if err := strictjson.ExactNames(params, "name", "arguments", "uri"); err != nil {
					return nil, isBatch, fmt.Errorf("mcp: %w", err)
				}
			}
		}
		var req Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, isBatch, fmt.Errorf("mcp: malformed request: %w", err)
		}
		out = append(out, req)
	}
	return out, isBatch, nil
}

func trimLeadingSpace(b []byte) []byte {
	for len(b) > 0 {
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			b = b[1:]
		default:
			return b
		}
	}
	return b
}
