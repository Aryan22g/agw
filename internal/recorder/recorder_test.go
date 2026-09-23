package recorder_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	gwaudit "github.com/Aryan22g/agw/internal/gateway/audit"
	"github.com/Aryan22g/agw/internal/recorder"
)

type ckSigner struct{ priv ed25519.PrivateKey }

func (s ckSigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(s.priv, m), nil }
func (s ckSigner) KeyID() string                 { return "test-ck" }

// testToken is presented by every export in these tests. The recorder
// refuses unauthenticated exports, so a test that forgot it would fail rather
// than quietly exercise a weaker configuration.
const testToken = "test-token-value"

type harness struct {
	srv  *httptest.Server
	rec  *recorder.Receiver
	sink *gwaudit.EvidenceSink
	path string
	pub  ed25519.PublicKey
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	sink, err := gwaudit.NewEvidenceSink(gwaudit.EvidenceSinkConfig{
		Path: path, Signer: ckSigner{priv}, KeyID: "test-ck", CheckpointEvery: 5,
	})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	rec, err := recorder.New(recorder.Config{Sink: sink, Token: testToken})
	if err != nil {
		t.Fatalf("receiver: %v", err)
	}
	srv := httptest.NewServer(rec.Handler())
	t.Cleanup(srv.Close)

	return &harness{srv: srv, rec: rec, sink: sink, path: path, pub: pub}
}

func (h *harness) export(t *testing.T, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/traces", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("build export: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return resp
}

func (h *harness) records(t *testing.T) []gwaudit.Record {
	t.Helper()
	if err := h.sink.Checkpoint(); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	f, err := os.Open(h.path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	recs, err := gwaudit.ReadRecords(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return recs
}

// A realistic export from an agent making a tool call and an HTTP request,
// shaped the way an OpenTelemetry SDK actually emits it.
const agentExport = `{
 "resourceSpans": [{
  "resource": {"attributes": [
    {"key":"service.name","value":{"stringValue":"research-agent"}},
    {"key":"service.namespace","value":{"stringValue":"acme"}}
  ]},
  "scopeSpans": [{
   "spans": [
    {
     "traceId":"5b8efff798038103d269b633813fc60c",
     "spanId":"eee19b7ec3c1b174",
     "name":"tool github_search",
     "startTimeUnixNano":"1789000000000000000",
     "endTimeUnixNano":"1789000000500000000",
     "attributes":[
       {"key":"gen_ai.tool.name","value":{"stringValue":"github_search"}},
       {"key":"gen_ai.tool.call.id","value":{"stringValue":"call_abc"}}
     ],
     "status":{"code":1}
    },
    {
     "traceId":"5b8efff798038103d269b633813fc60c",
     "spanId":"aaa19b7ec3c1b175",
     "name":"GET",
     "startTimeUnixNano":"1789000001000000000",
     "endTimeUnixNano":"1789000001250000000",
     "attributes":[
       {"key":"http.request.method","value":{"stringValue":"GET"}},
       {"key":"url.full","value":{"stringValue":"https://api.github.com/repos/acme/app"}},
       {"key":"server.address","value":{"stringValue":"api.github.com"}}
     ],
     "status":{"code":1}
    },
    {
     "traceId":"5b8efff798038103d269b633813fc60c",
     "spanId":"bbb19b7ec3c1b176",
     "name":"POST",
     "startTimeUnixNano":"1789000002000000000",
     "endTimeUnixNano":"1789000002100000000",
     "attributes":[
       {"key":"http.request.method","value":{"stringValue":"POST"}},
       {"key":"url.full","value":{"stringValue":"http://169.254.169.254/latest/meta-data/"}},
       {"key":"server.address","value":{"stringValue":"169.254.169.254"}}
     ],
     "status":{"code":2},
     "statusMessage":"connection refused"
    }
   ]
  }]
 }]
}`

// TestExportBecomesVerifiableEvidence is the whole of Level 0: telemetry the
// agent already emits goes in, a chain anyone can verify comes out.
func TestExportBecomesVerifiableEvidence(t *testing.T) {
	h := newHarness(t)

	resp := h.export(t, agentExport)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export returned %d", resp.StatusCode)
	}

	recs := h.records(t)
	if len(recs) != 3 {
		t.Fatalf("recorded %d spans, want 3", len(recs))
	}

	for _, r := range recs {
		if r.EventName != recorder.EventAgentActivity {
			t.Errorf("event = %q, want %q", r.EventName, recorder.EventAgentActivity)
		}
		if r.Event.AgentID != "research-agent" {
			t.Errorf("agent = %q, want research-agent", r.Event.AgentID)
		}
		if r.Event.TenantID != "acme" {
			t.Errorf("tenant = %q, want acme", r.Event.TenantID)
		}
		// Self-reported activity must be distinguishable from an enforced
		// decision, or a compromised agent's telemetry reads as verified.
		if r.Event.RouteID != "self-reported" {
			t.Errorf("record is not marked self-reported: %q", r.Event.RouteID)
		}
	}

	// The chain verifies with the file and a public key, nothing else.
	if err := h.sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	f, err := os.Open(h.path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	result, problems, err := gwaudit.Verify(f, h.pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, p := range problems {
		t.Errorf("verification problem: %s", p.Error())
	}
	if result.Records != 3 {
		t.Errorf("verified %d records, want 3", result.Records)
	}
}

func TestSemanticConventionsAreMapped(t *testing.T) {
	h := newHarness(t)
	resp := h.export(t, agentExport)
	defer resp.Body.Close()

	recs := h.records(t)
	byAction := map[string]gwaudit.GatewayEvent{}
	for _, r := range recs {
		byAction[r.Event.Action] = r.Event
	}

	tool, ok := byAction["tool.github_search"]
	if !ok {
		t.Fatalf("tool span was not mapped; actions were %v", keysOf(byAction))
	}
	if tool.ResourceID != "call_abc" {
		t.Errorf("tool resource = %q", tool.ResourceID)
	}

	get, ok := byAction["http.get"]
	if !ok {
		t.Fatal("http span was not mapped")
	}
	if get.BackendID != "api.github.com" {
		t.Errorf("http target = %q, want api.github.com", get.BackendID)
	}

	// An error span must not be recorded as a success.
	post, ok := byAction["http.post"]
	if !ok {
		t.Fatal("errored span was not mapped")
	}
	if post.Decision != "error" {
		t.Errorf("errored span recorded as %q, want error", post.Decision)
	}
	if post.BackendID != "169.254.169.254" {
		t.Errorf("target = %q", post.BackendID)
	}
}

// TestTraceIdsSurviveBothEncodings: the OTel spec says hex for OTLP/JSON,
// protobuf's JSON mapping says base64 for bytes, and exporters exist that do
// each. Refusing one would mean telling a user their pipeline is wrong.
func TestTraceIdsSurviveBothEncodings(t *testing.T) {
	h := newHarness(t)

	raw, _ := hex.DecodeString("5b8efff798038103d269b633813fc60c")
	b64 := base64.StdEncoding.EncodeToString(raw)

	body := fmt.Sprintf(`{"resourceSpans":[{"resource":{"attributes":[
	  {"key":"service.name","value":{"stringValue":"a"}}]},
	 "scopeSpans":[{"spans":[
	  {"traceId":"%s","spanId":"eee19b7ec3c1b174","name":"x",
	   "startTimeUnixNano":"1789000000000000000","endTimeUnixNano":"1789000000100000000",
	   "status":{"code":1}}]}]}]}`, b64)

	resp := h.export(t, body)
	defer resp.Body.Close()

	recs := h.records(t)
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	if recs[0].Event.TraceID != "5b8efff798038103d269b633813fc60c" {
		t.Errorf("base64 trace id decoded to %q", recs[0].Event.TraceID)
	}
}

// TestIntegerAttributesEncodedEitherWay: protobuf JSON encodes 64-bit ints as
// strings, but exporters emit plain numbers too.
func TestIntegerAttributesEncodedEitherWay(t *testing.T) {
	h := newHarness(t)

	body := `{"resourceSpans":[{"resource":{"attributes":[
	  {"key":"service.name","value":{"stringValue":"a"}}]},
	 "scopeSpans":[{"spans":[
	  {"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174","name":"x",
	   "startTimeUnixNano":1789000000000000000,"endTimeUnixNano":1789000000100000000,
	   "status":{"code":1}}]}]}]}`

	resp := h.export(t, body)
	defer resp.Body.Close()

	recs := h.records(t)
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	if recs[0].Event.StartedAt.IsZero() {
		t.Error("numeric timestamps were not parsed")
	}
}

// TestUnattributedSpansAreStillRecorded: a gap in the evidence must not look
// like an absence of activity.
func TestUnattributedSpansAreStillRecorded(t *testing.T) {
	h := newHarness(t)

	body := `{"resourceSpans":[{"resource":{"attributes":[]},
	 "scopeSpans":[{"spans":[
	  {"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174","name":"mystery",
	   "startTimeUnixNano":"1789000000000000000","endTimeUnixNano":"1789000000100000000",
	   "status":{"code":1}}]}]}]}`

	resp := h.export(t, body)
	defer resp.Body.Close()

	recs := h.records(t)
	if len(recs) != 1 {
		t.Fatalf("an unattributable span was dropped; got %d records", len(recs))
	}
	if recs[0].Event.AgentID != "unattributed" {
		t.Errorf("agent = %q, want unattributed", recs[0].Event.AgentID)
	}
}

// TestSinkFailureIsReportedAsPartialSuccess: an exporter must learn that its
// spans were not recorded, rather than believing a full disk was a success.
func TestSinkFailureIsReportedAsPartialSuccess(t *testing.T) {
	rec, err := recorder.New(recorder.Config{Sink: failingSink{}, Token: testToken})
	if err != nil {
		t.Fatalf("receiver: %v", err)
	}
	srv := httptest.NewServer(rec.Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/traces", bytes.NewBufferString(agentExport))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	var out struct {
		PartialSuccess struct {
			RejectedSpans string `json:"rejectedSpans"`
		} `json:"partialSuccess"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.PartialSuccess.RejectedSpans != "3" {
		t.Errorf("rejectedSpans = %q, want 3", out.PartialSuccess.RejectedSpans)
	}
}

type failingSink struct{}

func (failingSink) Write(context.Context, string, gwaudit.GatewayEvent) (gwaudit.Record, error) {
	return gwaudit.Record{}, errors.New("evidence disk is full")
}

func keysOf(m map[string]gwaudit.GatewayEvent) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestUnauthenticatedExportIsRejected.
//
// Records cannot be altered once written -- the chain prevents that -- but an
// unauthenticated port lets anything that reaches it APPEND, and the
// producer's next signed checkpoint then vouches for the injected records as
// readily as its own. The producer signs them without knowing.
func TestUnauthenticatedExportIsRejected(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"wrong token", "Bearer not-the-token"},
		{"empty bearer", "Bearer "},
		{"wrong scheme", "Basic " + testToken},
		{"token without scheme", testToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/traces",
				bytes.NewBufferString(agentExport))
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
		})
	}

	if len(h.records(t)) != 0 {
		t.Error("an unauthenticated export still wrote records to the chain")
	}
}

// TestRecorderRefusesToStartWithoutATokenOrAnExplicitOptOut.
func TestRecorderRefusesToStartWithoutATokenOrAnExplicitOptOut(t *testing.T) {
	if _, err := recorder.New(recorder.Config{Sink: failingSink{}}); err == nil {
		t.Error("the recorder started with no token and no explicit opt-out")
	}
	if _, err := recorder.New(recorder.Config{
		Sink: failingSink{}, AllowUnauthenticated: true,
	}); err != nil {
		t.Errorf("an explicit opt-out was refused: %v", err)
	}
}

// TestRecordsAreMarkedObserved: a reader must be able to tell self-reported
// activity from an enforced decision, and now the marker is covered by the
// chain hash rather than being a convention.
func TestRecordsAreMarkedObserved(t *testing.T) {
	h := newHarness(t)
	resp := h.export(t, agentExport)
	defer resp.Body.Close()

	for _, r := range h.records(t) {
		if r.Event.Producer != gwaudit.ProducerRecorder {
			t.Errorf("producer = %q, want %q", r.Event.Producer, gwaudit.ProducerRecorder)
		}
		if gwaudit.Enforced(r.Event.Producer) {
			t.Error("a self-reported record claims to be enforced")
		}
	}
}
