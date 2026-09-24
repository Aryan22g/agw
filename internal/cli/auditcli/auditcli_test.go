package auditcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Aryan22g/agw/internal/gateway/audit"
)

type edSigner struct{ priv ed25519.PrivateKey }

func (s edSigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(s.priv, m), nil }
func (s edSigner) KeyID() string                 { return "k" }

// fixture writes a small signed chain and its public key file.
func fixture(t *testing.T, n int) (evidence, pubFile, pubB64 string) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	evidence = filepath.Join(dir, "ev.jsonl")
	sink, err := audit.NewEvidenceSink(audit.EvidenceSinkConfig{
		Path: evidence, Signer: edSigner{priv}, KeyID: "k", CheckpointEvery: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		decision := "allow"
		if i%2 == 1 {
			decision = "deny"
		}
		if _, err := sink.Write(context.Background(), "confine.egress", audit.GatewayEvent{
			AgentID: "a1", Action: "net.connect", ResourceID: "pypi.org:443",
			Decision: decision, ReasonCode: "not_in_allowlist",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	_ = sink.Close()

	pubB64 = base64.StdEncoding.EncodeToString(pub)
	pubFile = filepath.Join(dir, "cp.pub")
	if err := os.WriteFile(pubFile, []byte(pubB64+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return evidence, pubFile, pubB64
}

func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := Out
	Out = &buf
	t.Cleanup(func() { Out = old })
	return &buf
}

// TestVerifyAcceptsEveryDocumentedSpelling pins the defect that started this
// package: the command `agw` printed for users did not run. Every form that
// has appeared in the docs or in printed hints must now work.
func TestVerifyAcceptsEveryDocumentedSpelling(t *testing.T) {
	ev, pubFile, pubB64 := fixture(t, 4)

	spellings := map[string][]string{
		"positional then --key file":   {ev, "--key", pubFile},
		"--key file then positional":   {"--key", pubFile, ev},
		"legacy -log -public-key b64":  {"-log", ev, "-public-key", pubB64},
		"legacy -log -public-key file": {"-log", ev, "-public-key", pubFile},
		"--key base64 value":           {ev, "--key", pubB64},
	}
	for name, args := range spellings {
		t.Run(name, func(t *testing.T) {
			out := capture(t)
			if err := Verify("agw", args); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if !strings.Contains(out.String(), "VERIFIED —") {
				t.Fatalf("did not verify:\n%s", out)
			}
		})
	}
}

func TestVerifyExitsTwoOnTampering(t *testing.T) {
	ev, pubFile, _ := fixture(t, 4)
	raw, _ := os.ReadFile(ev)
	bad := bytes.Replace(raw, []byte(`"Decision":"deny"`), []byte(`"Decision":"allow"`), 1)
	if bytes.Equal(raw, bad) {
		t.Fatal("fixture has no deny record to alter")
	}
	_ = os.WriteFile(ev, bad, 0o600)

	capture(t)
	err := Verify("agw", []string{ev, "--key", pubFile})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("want ExitError code 2 for a tampered log, got %v", err)
	}
}

func TestVerifyJSONIsMachineReadable(t *testing.T) {
	ev, pubFile, _ := fixture(t, 3)
	out := capture(t)
	if err := Verify("agw", []string{ev, "--key", pubFile, "--json"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"intact": true`, `"records": 3`, `"signatures_checked": true`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("JSON output lacks %s:\n%s", want, out)
		}
	}
}

func TestLoadPublicKeyExplainsAMissingFile(t *testing.T) {
	_, err := LoadPublicKey("/nonexistent/dir/checkpoint.pub")
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("a missing key file should say so, got %v", err)
	}
}

func TestShowFilters(t *testing.T) {
	ev, _, _ := fixture(t, 6)
	out := capture(t)
	if err := Show("agw", []string{ev, "--denied"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "3 of 6 record(s) matched") {
		t.Fatalf("--denied should match the 3 deny records:\n%s", out)
	}

	out.Reset()
	if err := Show("agw", []string{ev, "--since", "1h", "--agent", "nobody"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "0 of 6") {
		t.Fatalf("agent filter did not apply:\n%s", out)
	}
}

func TestSinceAcceptsDurations(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	got, err := parseSince("90m", now)
	if err != nil || !got.Equal(now.Add(-90*time.Minute)) {
		t.Fatalf("90m: %v %v", got, err)
	}
	if _, err := parseSince("yesterday", now); err == nil {
		t.Fatal("nonsense should be refused with guidance")
	}
}

// TestTailFollowsAppendedRecords exercises follow against a live sink.
func TestTailFollowsAppendedRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.jsonl")
	sink, err := audit.NewEvidenceSink(audit.EvidenceSinkConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	followPoll = 10 * time.Millisecond
	followStop = make(chan struct{})

	got := make(chan audit.Record, 10)
	done := make(chan error, 1)
	go func() {
		done <- follow(path, showFilter{decision: "deny"}, func(r audit.Record) { got <- r })
	}()

	for i := 0; i < 4; i++ {
		d := "allow"
		if i >= 2 {
			d = "deny"
		}
		if _, err := sink.Write(context.Background(), "e", audit.GatewayEvent{AgentID: "a", Decision: d}); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 2; i++ {
		select {
		case r := <-got:
			if r.Event.Decision != "deny" {
				t.Fatalf("filter let through %q", r.Event.Decision)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d of 2 appended deny records were followed", i)
		}
	}
	close(followStop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestTailNoticesTruncation: an evidence log that shrinks while followed has
// been edited, and that is itself the finding.
func TestTailNoticesTruncation(t *testing.T) {
	ev, _, _ := fixture(t, 5)
	followPoll = 10 * time.Millisecond
	followStop = make(chan struct{})
	defer close(followStop)

	done := make(chan error, 1)
	go func() { done <- follow(ev, showFilter{}, func(audit.Record) {}) }()
	time.Sleep(100 * time.Millisecond)
	if err := os.Truncate(ev, 10); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != 2 {
			t.Fatalf("want exit 2 on truncation, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("truncation went unnoticed")
	}
}

// TestVerifyCallsAnEmptyLogEmpty: exit 0, because nothing in the log is
// wrong, but never "VERIFIED" -- an empty log is also what deleting every
// record leaves, and only an anchor tells the two apart (RFC-0009 §6.4).
func TestVerifyCallsAnEmptyLogEmpty(t *testing.T) {
	_, pubFile, _ := fixture(t, 1)
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{empty, "--key", pubFile}, {empty}} {
		out := capture(t)
		if err := Verify("agw", args); err != nil {
			t.Fatalf("%v: %v", args[1:], err)
		}
		if !strings.Contains(out.String(), "EMPTY —") || strings.Contains(out.String(), "VERIFIED") {
			t.Errorf("%v: want EMPTY and no VERIFIED:\n%s", args[1:], out)
		}
	}
}

// TestVerifyCallsAnUnsignedLogUnsignedNotTampered: a log with no checkpoint
// fails (exit 2) -- it proves nothing -- but nothing in it contradicts
// anything, so the verdict must not accuse anyone of tampering.
func TestVerifyCallsAnUnsignedLogUnsignedNotTampered(t *testing.T) {
	ev, pubFile, _ := fixture(t, 3)
	raw, _ := os.ReadFile(ev)
	var kept []string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if !strings.Contains(l, `"type":"checkpoint"`) {
			kept = append(kept, l)
		}
	}
	_ = os.WriteFile(ev, []byte(strings.Join(kept, "\n")+"\n"), 0o600)

	out := capture(t)
	err := Verify("agw", []string{ev, "--key", pubFile})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("want exit 2 for an unsigned log, got %v", err)
	}
	if !strings.Contains(out.String(), "NOT VERIFIED — nothing in this log is signed") ||
		strings.Contains(out.String(), "TAMPERING") {
		t.Fatalf("unsigned log verdict:\n%s", out)
	}
}
