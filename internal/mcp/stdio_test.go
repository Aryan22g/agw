package mcp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Aryan22g/agw/internal/mcp"
)

// fakeStdioServer answers like a stdio MCP server, parsing the way a
// JavaScript or Python one does, and reports every tool it executed.
func fakeStdioServer(in io.Reader, out io.WriteCloser, executed chan<- string) {
	// A real stdio server exits when its input ends, which closes its
	// output; the proxy relies on that to know the last response is out.
	defer out.Close()
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := sc.Bytes()
		method, tool := executedBy(line)
		var msg map[string]json.RawMessage
		_ = json.Unmarshal(line, &msg)
		id := string(msg["id"])
		switch method {
		case "tools/list":
			io.WriteString(out, `{"jsonrpc":"2.0","id":`+id+`,"result":{"tools":[{"name":"search_tickets","description":"Search","inputSchema":{}}]}}`+"\n")
		case "tools/call":
			executed <- tool
			io.WriteString(out, `{"jsonrpc":"2.0","id":`+id+`,"result":{"content":[{"type":"text","text":"ran `+tool+`"}]}}`+"\n")
		case "initialize":
			io.WriteString(out, `{"jsonrpc":"2.0","id":`+id+`,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}`+"\n")
			// A server-initiated request, which the client answers.
			io.WriteString(out, `{"jsonrpc":"2.0","id":"srv-1","method":"roots/list"}`+"\n")
		}
	}
}

func TestStdioEnforcement(t *testing.T) {
	h := newHarness(t)
	e, err := mcp.NewEnforcer(mcp.Config{Authorizer: engineFor(t), Sink: h.sink,
		TenantID: "acme", AgentID: "support-agent"}, "stdio:fake-server")
	if err != nil {
		t.Fatal(err)
	}

	clientR, clientW := io.Pipe() // client -> agw
	outR, outW := io.Pipe()       // agw -> client
	serverInR, serverInW := io.Pipe()
	serverOutR, serverOutW := io.Pipe()
	executed := make(chan string, 10)
	go fakeStdioServer(serverInR, serverOutW, executed)

	done := make(chan error, 1)
	go func() { done <- e.ServeStdio(context.Background(), clientR, outW, serverInW, serverOutR) }()

	replies := bufio.NewScanner(outR)
	send := func(s string) { io.WriteString(clientW, s+"\n") }
	next := func() string {
		ch := make(chan string, 1)
		go func() {
			if replies.Scan() {
				ch <- replies.Text()
			}
		}()
		select {
		case s := <-ch:
			return s
		case <-time.After(3 * time.Second):
			t.Fatal("no reply")
			return ""
		}
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if r := next(); !strings.Contains(r, "protocolVersion") {
		t.Fatalf("initialize: %s", r)
	}
	if r := next(); !strings.Contains(r, "roots/list") {
		t.Fatalf("server-initiated request should reach the client: %s", r)
	}
	// The client's answer to the server's request passes straight through.
	send(`{"jsonrpc":"2.0","id":"srv-1","result":{"roots":[]}}`)

	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if r := next(); !strings.Contains(r, "search_tickets") {
		t.Fatalf("tools/list: %s", r)
	}

	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_tickets","arguments":{}}}`)
	if r := next(); !strings.Contains(r, "ran search_tickets") {
		t.Fatalf("permitted call: %s", r)
	}
	if got := <-executed; got != "search_tickets" {
		t.Fatalf("executed %q", got)
	}

	send(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_account","arguments":{}}}`)
	if r := next(); !strings.Contains(r, `"id":4`) || !strings.Contains(r, "-32001") {
		t.Fatalf("denied call should be answered with a policy error for id 4: %s", r)
	}

	// The parser-differential attack over stdio.
	send(`{"jsonrpc":"2.0","id":5,"method":"tools/call","Method":"ping","params":{"name":"delete_account"}}`)
	if r := next(); !strings.Contains(r, "-32600") {
		t.Fatalf("ambiguous message: %s", r)
	}

	clientW.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeStdio: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServeStdio did not return after the client closed")
	}
	close(executed)
	for tool := range executed {
		if tool == "delete_account" {
			t.Fatal("a forbidden tool reached the server over stdio")
		}
	}

	allowed, denied, _ := e.Stats()
	if allowed != 1 || denied != 2 {
		t.Errorf("stats: allowed %d denied %d, want 1 and 2", allowed, denied)
	}
}
