package mcp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Aryan22g/agw/internal/mcp"
	"github.com/Aryan22g/agw/pkg/authz"
)

// executedBy parses a JSON-RPC message the way the servers people actually
// run do -- JavaScript's JSON.parse and Python's json: member names are
// case-SENSITIVE and a repeated name takes the last value -- and returns the
// method and tool name that server would act on.
func executedBy(body []byte) (method, tool string) {
	var msg map[string]json.RawMessage
	if json.Unmarshal(body, &msg) != nil {
		return "", ""
	}
	_ = json.Unmarshal(msg["method"], &method)
	var params map[string]json.RawMessage
	_ = json.Unmarshal(msg["params"], &params)
	_ = json.Unmarshal(params["name"], &tool)
	return method, tool
}

// TestEnforcementPointAndServerReadTheSameCall pins a policy bypass.
//
// encoding/json matches member names case-insensitively and keeps the last
// value; a JavaScript or Python MCP server matches exactly. A message carrying
// both "method" and "Method" was therefore read by the enforcement point as
// one call and executed by the server as another: the guardrail-denied tool
// could be run by labelling the request, for the proxy's benefit only, as an
// ungated method such as initialize.
func TestEnforcementPointAndServerReadTheSameCall(t *testing.T) {
	var (
		mu       sync.Mutex
		executed []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		if m, tool := executedBy(body); m == "tools/call" {
			mu.Lock()
			executed = append(executed, tool)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer server.Close()

	h := newHarness(t)
	up, _ := url.Parse(server.URL)
	p, err := mcp.New(mcp.Config{
		Upstream: up, Authorizer: engineFor(t), Sink: h.sink,
		TenantID: "acme", AgentID: "support-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(p)
	defer front.Close()

	attacks := map[string]string{
		"method case variant": `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"initialize","params":{"name":"delete_account","arguments":{}}}`,
		"name case variant":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_account","Name":"search_tickets","arguments":{}}}`,
		"duplicate method":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"initialize","params":{"name":"delete_account"}}`,
		"duplicate name":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_account","name":"search_tickets"}}`,
		"params case variant": `{"jsonrpc":"2.0","id":1,"method":"tools/call","Params":{"name":"search_tickets"},"params":{"name":"delete_account"}}`,
		"batch member":        `[{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"delete_account"}}]`,
	}
	for name, body := range attacks {
		resp, err := http.Post(front.URL, "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		mu.Lock()
		for _, tool := range executed {
			if tool == "delete_account" {
				t.Errorf("%s: the server executed delete_account, which policy forbids", name)
			}
		}
		executed = nil
		mu.Unlock()
	}
}

func engineFor(t *testing.T) *authz.NativeEngine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acme.yaml")
	if err := os.WriteFile(path, []byte(policyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := authz.LoadPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := authz.NewNativeEngine(map[string]*authz.Policy{"acme": p})
	if err != nil {
		t.Fatal(err)
	}
	return e
}
