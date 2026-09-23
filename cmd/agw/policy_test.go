package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Aryan22g/agw/internal/gateway/audit"
)

func writeEvidence(t *testing.T, events []audit.GatewayEvent) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ev.jsonl")
	sink, err := audit.NewEvidenceSink(audit.EvidenceSinkConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if _, err := sink.Write(context.Background(), "e", ev); err != nil {
			t.Fatal(err)
		}
	}
	_ = sink.Close()
	return path
}

// TestSuggestDraftsObservedButNeverGuardedOrEnforcedRefusals pins the two
// rules that keep `policy suggest` from being a rubber stamp.
func TestSuggestDraftsObservedButNeverGuardedOrEnforcedRefusals(t *testing.T) {
	ev := writeEvidence(t, []audit.GatewayEvent{
		// Observed in shadow mode: nothing blocked, the agent reached it.
		{AgentID: "w", Action: "http.get", ResourceID: "https://pypi.org/simple/x", Decision: "would_deny", ReasonCode: "not_in_allowlist"},
		{AgentID: "w", Action: "http.get", ResourceID: "https://pypi.org/simple/y", Decision: "observed"},
		// Path-only URL with the host carried separately.
		{AgentID: "w", Action: "http.post", ResourceID: "/v1/upload", BackendID: "files.example.com", Decision: "observed"},
		// The metadata endpoint, however it was reached, is never drafted.
		{AgentID: "w", Action: "http.get", ResourceID: "http://169.254.169.254/latest/", Decision: "observed"},
		// Refused by an enforcement point: an attempt, not a need.
		{AgentID: "w", Action: "net.connect", ResourceType: "host", ResourceID: "c2.evil.net:443", Decision: "deny", ReasonCode: "not_in_allowlist"},
	})
	out := filepath.Join(t.TempDir(), "draft.yaml")
	if err := runPolicySuggest([]string{ev, "--out", out}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	draft := string(raw)

	allowSection := draft[:strings.Index(draft, "permit_private")]
	for _, want := range []string{"host: pypi.org", "observed 2 time(s)", "host: files.example.com"} {
		if !strings.Contains(allowSection, want) {
			t.Errorf("draft should contain %q:\n%s", want, draft)
		}
	}
	for _, never := range []string{"169.254.169.254", "c2.evil.net"} {
		if strings.Contains(allowSection, never) {
			t.Errorf("draft must not allow %s:\n%s", never, draft)
		}
		if !strings.Contains(draft, "#   "+never) {
			t.Errorf("%s should be listed as left out, so the omission is visible:\n%s", never, draft)
		}
	}

	errs, _ := lintOne(out)
	if len(errs) > 0 {
		t.Fatalf("a drafted policy must lint clean: %v", errs)
	}

	// Never overwrite a policy someone may have edited.
	if err := runPolicySuggest([]string{ev, "--out", out}); err == nil {
		t.Fatal("suggest overwrote an existing file")
	}
}

func TestLintCatchesWhatStartupWouldRefuse(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o644)
		return p
	}

	// Passes the document validator, fails when the guard is built. A lint
	// that stopped at the first half would call this file fine.
	linklocal := write("ll.yaml", "version: \"1\"\nworkloads:\n  - id: w\n    allow:\n      - host: a.example\n        ports: [443]\npermit_private: [169.254.169.0/24]\n")
	if errs, _ := lintOne(linklocal); len(errs) == 0 {
		t.Error("a permit_private entry covering link-local space passed lint")
	}

	noPorts := write("np.yaml", "version: \"1\"\nworkloads:\n  - id: w\n    allow:\n      - host: a.example\n")
	errs, warns := lintOne(noPorts)
	if len(errs) > 0 || len(warns) == 0 {
		t.Errorf("a rule with no ports should lint with a warning, got errs=%v warns=%v", errs, warns)
	}

	action := write("act.yaml", "tenant: t\nversion: \"1\"\nrules:\n  - id: r\n    effect: allow\n    agents: [a]\n    actions: [\"mcp.tool.*\"]\n")
	if errs, _ := lintOne(action); len(errs) > 0 {
		t.Errorf("valid action policy failed lint: %v", errs)
	}

	junk := write("junk.yaml", "hello: world\n")
	if errs, _ := lintOne(junk); len(errs) == 0 {
		t.Error("an unrecognisable file passed lint")
	}
}

func TestDefaultCheckpointKeyIsCreatedOnceAndReused(t *testing.T) {
	t.Setenv("AGW_HOME", t.TempDir())
	t.Setenv("AGW_CHECKPOINT_KEY", "")

	first, err := resolveCheckpointKey("")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if first.signer == nil || first.PubPath == "" {
		t.Fatal("the default path must produce a signing key and a public key file")
	}
	if !strings.Contains(first.Source, "generated") {
		t.Errorf("first use should say the key was generated: %s", first.Source)
	}
	info, _ := os.Stat(strings.TrimSuffix(first.PubPath, ".pub"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key mode %o, want 600", info.Mode().Perm())
	}

	second, err := resolveCheckpointKey("")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.keyID != first.keyID {
		t.Fatal("the default key changed between runs, which would orphan every earlier chain")
	}

	none, err := resolveCheckpointKey("none")
	if err != nil || none.signer != nil {
		t.Fatalf("--key none should mean unsigned: %v", err)
	}

	if _, err := resolveCheckpointKey(filepath.Join(t.TempDir(), "missing.key")); err == nil {
		t.Fatal("an explicit path that does not exist must be an error, not a silently generated key")
	}
}
