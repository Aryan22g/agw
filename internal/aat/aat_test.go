package aat

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Aryan22g/agw/pkg/evidence"
)

type edSigner struct{ priv ed25519.PrivateKey }

func (s edSigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(s.priv, m), nil }
func (s edSigner) KeyID() string                 { return "k" }

// chain writes a realistic mixed chain: confinement, MCP, gateway, recorder.
func chain(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "ev.jsonl")
	sink, err := evidence.NewEvidenceSink(evidence.EvidenceSinkConfig{Path: path, Signer: edSigner{priv}, KeyID: "k", CheckpointEvery: 3})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	events := []struct {
		name string
		ev   evidence.GatewayEvent
	}{
		{"confine.workload.registered", evidence.GatewayEvent{TenantID: "local", AgentID: "eval-1", Decision: "allow", ReasonCode: "attested", Producer: evidence.ProducerConfineProxy}},
		{"confine.egress.denied", evidence.GatewayEvent{TenantID: "local", AgentID: "eval-1", Action: "http.request", ResourceID: "169.254.169.254:80", Decision: "deny", ReasonCode: "metadata_endpoint", Producer: evidence.ProducerConfineProxy}},
		{"confine.egress.allowed", evidence.GatewayEvent{TenantID: "local", AgentID: "eval-1", Action: "net.connect", ResourceID: "pypi.org:443", Decision: "allow", ReasonCode: "allowed", Producer: evidence.ProducerConfineProxy, LatencyMS: 3}},
		{"confine.egress.closed", evidence.GatewayEvent{TenantID: "local", AgentID: "eval-1", Action: "net.connect", ResourceID: "pypi.org:443", Decision: "allow", ReasonCode: "closed", Producer: evidence.ProducerConfineProxy}},
		{"mcp.tool.call", evidence.GatewayEvent{TenantID: "acme", AgentID: "support", Action: "mcp.tool.delete_repo", Decision: "deny", ReasonCode: "policy_denied", Producer: evidence.ProducerMCP, Risk: "destructive"}},
		{"gateway.decision", evidence.GatewayEvent{TenantID: "acme", AgentID: "partner/bot", KeyID: "kid", Action: "github.issue.create", Decision: "allow", Producer: evidence.ProducerGateway, Federated: true}},
		{"gateway.decision", evidence.GatewayEvent{TenantID: "acme", AgentID: "billing", KeyID: "kid", Action: "billing.refund", Decision: "deny", ReasonCode: "credential_revoked", Producer: evidence.ProducerGateway}},
		{"agent.activity", evidence.GatewayEvent{AgentID: "research-agent", Action: "tool.web_search", ResourceID: "call_1", Decision: "would_deny", ReasonCode: "not_in_allowlist", Producer: evidence.ProducerRecorder}},
		{"agent.activity", evidence.GatewayEvent{AgentID: "research-agent", Action: "http.get", ResourceID: "https://x.example/", Decision: "error", Producer: evidence.ProducerRecorder, StartedAt: now}},
	}
	for _, e := range events {
		if _, err := sink.Write(context.Background(), e.name, e.ev); err != nil {
			t.Fatal(err)
		}
	}
	_ = sink.Checkpoint()
	_ = sink.Close()
	return path, pub
}

func convertFile(t *testing.T, path string, pub ed25519.PublicKey) ([]Record, []byte) {
	t.Helper()
	f, _ := os.Open(path)
	res, _, err := evidence.Verify(f, pub)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	f, _ = os.Open(path)
	recs, _ := evidence.ReadRecords(f)
	f.Close()
	out, err := Convert(recs, res, Options{Source: "ev.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return out, data
}

// TestExportPassesTheDraftsOwnChecks: the conversion is held to -04's
// verifier obligations, mandatory fields and enumerations.
func TestExportPassesTheDraftsOwnChecks(t *testing.T) {
	path, pub := chain(t)
	out, data := convertFile(t, path, pub)
	if errs := Check(bytes.NewReader(data)); len(errs) > 0 {
		t.Fatalf("export fails the draft's checks: %v", errs)
	}
	if len(out) != 10 {
		t.Fatalf("%d records, want genesis + 9", len(out))
	}

	byEvent := map[string]Record{}
	for _, r := range out[1:] {
		d := r["action_detail"].(map[string]any)
		byEvent[d["agw_event"].(string)+"/"+r["agent_id"].(string)] = r
	}

	imds := byEvent["confine.egress.denied/urn:agw:agent:local:eval-1"]
	if imds["outcome"] != "denied" || imds["record_phase"] != "pre_execution" ||
		imds["recording_component"] != "urn:agw:producer:enforced:confine-proxy" {
		t.Errorf("confinement denial mapped wrongly: %v", imds)
	}
	if got := imds["deny_reasons"].([]string); got[0] != "AGW_METADATA_ENDPOINT" {
		t.Errorf("deny_reasons = %v", got)
	}
	if byEvent["confine.workload.registered/urn:agw:agent:local:eval-1"]["action_type"] != "lifecycle" {
		t.Error("workload registration should be a lifecycle record")
	}
	if byEvent["confine.egress.closed/urn:agw:agent:local:eval-1"]["record_phase"] != "post_execution" {
		t.Error("a closed connection is recorded after the action")
	}
	fed := byEvent["gateway.decision/urn:agw:agent:acme:partner%2Fbot"]
	if fed == nil || fed["trust_level"] != "L3" {
		t.Errorf("federated gateway call: agent id must be escaped and trust L3: %v", fed)
	}
	revoked := byEvent["gateway.decision/urn:agw:agent:acme:billing"]
	if revoked["deny_reasons"].([]string)[0] != "AGENT_REVOKED" || revoked["trust_level"] != "L2" {
		t.Errorf("revoked credential mapped wrongly: %v", revoked)
	}
	mcp := byEvent["mcp.tool.call/urn:agw:agent:acme:support"]
	if mcp["risk_score"] != 1.0 || mcp["deny_reasons"].([]string)[0] != "CAPABILITY_NOT_GRANTED" {
		t.Errorf("MCP denial mapped wrongly: %v", mcp)
	}
	shadow := byEvent["agent.activity/urn:agw:agent:research-agent"]
	if shadow == nil {
		t.Fatal("recorder records missing")
	}
	for _, r := range out {
		if r["agent_id"] == "urn:agw:agent:research-agent" && r["action_type"] != "tool_call" {
			t.Errorf("self-reported activity should be tool_call, got %v", r["action_type"])
		}
	}
}

// TestShadowVerdictIsNotADenial: nothing was blocked in shadow mode, so the
// action succeeded; the verdict is carried, not promoted to an outcome.
func TestShadowVerdictIsNotADenial(t *testing.T) {
	path, pub := chain(t)
	out, _ := convertFile(t, path, pub)
	for _, r := range out {
		d := r["action_detail"].(map[string]any)
		if d["agw_shadow_verdict"] == "would_deny" && r["outcome"] != "success" {
			t.Fatalf("shadow verdict became outcome %v", r["outcome"])
		}
	}
}

func TestExportIsDeterministic(t *testing.T) {
	path, pub := chain(t)
	_, a := convertFile(t, path, pub)
	_, b := convertFile(t, path, pub)
	if !bytes.Equal(a, b) {
		t.Fatal("two exports of one chain differ; parties could not compare them")
	}
}

func TestRefusesAChainThatDoesNotVerify(t *testing.T) {
	path, pub := chain(t)
	raw, _ := os.ReadFile(path)
	_ = os.WriteFile(path, bytes.Replace(raw, []byte(`"Decision":"deny"`), []byte(`"Decision":"allow"`), 1), 0o600)

	f, _ := os.Open(path)
	res, _, _ := evidence.Verify(f, pub)
	f.Close()
	f, _ = os.Open(path)
	recs, _ := evidence.ReadRecords(f)
	f.Close()
	if _, err := Convert(recs, res, Options{}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("converted a tampered chain: %v", err)
	}
}

// TestCheckCatchesABrokenLink makes sure Check is not vacuous.
func TestCheckCatchesABrokenLink(t *testing.T) {
	path, pub := chain(t)
	out, _ := convertFile(t, path, pub)
	d := out[3]["action_detail"].(map[string]any)
	d["agw_resource"] = "edited.example:443"
	data, _ := Marshal(out)
	errs := Check(bytes.NewReader(data))
	if len(errs) == 0 {
		t.Fatal("an edited AAT record passed the chain check")
	}
	if !strings.Contains(errs[0].Error(), "line 5") || !strings.Contains(errs[0].Error(), "prev_hash") {
		t.Errorf("the break should be reported at the record after the edit: %v", errs[0])
	}
	var probe map[string]any
	_ = json.Unmarshal(bytes.Split(data, []byte("\n"))[0], &probe)
	if probe["prev_hash"] != nil {
		t.Error("genesis prev_hash must be JSON null")
	}
}
