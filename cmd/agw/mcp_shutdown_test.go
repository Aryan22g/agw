//go:build !windows

package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Aryan22g/agw/internal/cli/auditcli"
	gwaudit "github.com/Aryan22g/agw/pkg/evidence"
)

// The test binary doubles as a fake MCP server: one that answers requests but,
// like servers started through npx, does not exit when its input closes.
func TestMain(m *testing.M) {
	if os.Getenv("AGW_TEST_FAKE_MCP_SERVER") == "1" {
		fakeMCPServer()
		return
	}
	os.Exit(m.Run())
}

func fakeMCPServer() {
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(in.Bytes(), &req) != nil || req.ID == nil {
			continue
		}
		result := map[string]any{}
		if req.Method == "tools/list" {
			result["tools"] = []any{}
		}
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		os.Stdout.Write(append(out, '\n'))
	}
	time.Sleep(time.Minute) // ignore end of input, as real servers often do
}

// TestMCPSessionIsSignedHoweverTheClientEndsIt pins a defect found by running
// agw mcp under Claude Code: the client ends a stdio server with SIGTERM and
// then SIGKILL, agw spent that time waiting for the server to exit before
// signing, and every session's evidence was left with no checkpoint -- it
// could not be verified.
func TestMCPSessionIsSignedHoweverTheClientEndsIt(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs agw")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "agw")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build agw: %v\n%s", err, out)
	}
	key, pubFile := filepath.Join(dir, "k"), filepath.Join(dir, "k.pub")
	if out, err := exec.Command(bin, "keygen", "--out", key, "--pub", pubFile).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	pub, err := auditcli.LoadPublicKey(pubFile)
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "p.yaml")
	os.WriteFile(policy, []byte("tenant: local\nversion: \"1\"\nrules:\n  - id: methods\n    effect: allow\n"+
		"    agents: [a]\n    actions: [\"mcp.method.*\"]\n    max_risk_class: destructive\n"), 0o644)

	cases := []struct {
		name string
		end  func(p *os.Process)
	}{
		{"SIGTERM, then SIGKILL 300ms later (Claude Code)", func(p *os.Process) {
			p.Signal(syscall.SIGTERM)
			time.Sleep(300 * time.Millisecond)
			p.Kill()
		}},
		{"SIGKILL with no warning, after the session goes quiet", func(p *os.Process) {
			time.Sleep(1500 * time.Millisecond)
			p.Kill()
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evidence := filepath.Join(dir, "ev"+string(rune('0'+i))+".jsonl")
			self, _ := os.Executable()
			cmd := exec.Command(bin, "mcp", "--policy", policy, "--agent", "a",
				"--evidence", evidence, "--key", key, "--", self)
			cmd.Env = append(os.Environ(), "AGW_TEST_FAKE_MCP_SERVER=1", "AGW_HOME="+dir)
			stdin, _ := cmd.StdinPipe()
			stdout, _ := cmd.StdoutPipe()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			replies := bufio.NewScanner(stdout)
			for id, method := range []string{"initialize", "tools/list", "tools/call"} {
				msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id + 1, "method": method,
					"params": map[string]any{"name": "delete_everything"}})
				stdin.Write(append(msg, '\n'))
				if !replies.Scan() {
					t.Fatalf("no reply to %s", method)
				}
			}
			tc.end(cmd.Process)
			cmd.Wait()

			f, err := os.Open(evidence)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			res, problems, err := gwaudit.Verify(f, ed25519.PublicKey(pub))
			if err != nil {
				t.Fatal(err)
			}
			if !res.Intact || res.Records < 3 || res.UnanchoredRecords != 0 {
				t.Fatalf("session evidence does not verify: intact=%v records=%d unanchored=%d problems=%v",
					res.Intact, res.Records, res.UnanchoredRecords, problems)
			}
		})
	}
}
