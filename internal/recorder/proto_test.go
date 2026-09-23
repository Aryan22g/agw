package recorder_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	gwaudit "github.com/Aryan22g/agw/internal/gateway/audit"
	"github.com/Aryan22g/agw/internal/recorder"
)

func str(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// agentExportProto is agentExport, span for span, as a protobuf exporter
// would send it.
func agentExportProto(t *testing.T) *coltracepb.ExportTraceServiceRequest {
	trace := mustHex(t, "5b8efff798038103d269b633813fc60c")
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			str("service.name", "research-agent"), str("service.namespace", "acme"),
		}},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{
			{
				TraceId: trace, SpanId: mustHex(t, "eee19b7ec3c1b174"), Name: "tool github_search",
				StartTimeUnixNano: 1789000000000000000, EndTimeUnixNano: 1789000000500000000,
				Attributes: []*commonpb.KeyValue{
					str("gen_ai.tool.name", "github_search"), str("gen_ai.tool.call.id", "call_abc"),
				},
				Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_OK},
			},
			{
				TraceId: trace, SpanId: mustHex(t, "aaa19b7ec3c1b175"), Name: "GET",
				StartTimeUnixNano: 1789000001000000000, EndTimeUnixNano: 1789000001250000000,
				Attributes: []*commonpb.KeyValue{
					str("http.request.method", "GET"),
					str("url.full", "https://api.github.com/repos/acme/app"),
					str("server.address", "api.github.com"),
				},
				Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_OK},
			},
			{
				TraceId: trace, SpanId: mustHex(t, "bbb19b7ec3c1b176"), Name: "POST",
				StartTimeUnixNano: 1789000002000000000, EndTimeUnixNano: 1789000002100000000,
				Attributes: []*commonpb.KeyValue{
					str("http.request.method", "POST"),
					str("url.full", "http://169.254.169.254/latest/meta-data/"),
					str("server.address", "169.254.169.254"),
				},
				Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR},
			},
		}}},
	}}}
}

func postProto(t *testing.T, h *harness, body []byte, gz bool) *http.Response {
	t.Helper()
	if gz {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		_, _ = w.Write(body)
		_ = w.Close()
		body = buf.Bytes()
	}
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/traces", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+testToken)
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// comparable strips the fields that legitimately differ between two
// recordings of the same span -- when it was recorded, and where it sits in
// the chain -- and keeps everything that describes the agent's action.
func comparable(recs []gwaudit.Record) []gwaudit.GatewayEvent {
	out := make([]gwaudit.GatewayEvent, 0, len(recs))
	for _, r := range recs {
		ev := r.Event
		ev.EventID, ev.DecisionID, ev.RequestID = "", "", ""
		out = append(out, ev)
	}
	return out
}

// TestProtobufAndJSONProduceIdenticalEvidence is the property that makes
// accepting both encodings safe: the same agent action must produce the same
// record whichever exporter setting a team left on.
func TestProtobufAndJSONProduceIdenticalEvidence(t *testing.T) {
	jsonH := newHarness(t)
	resp := jsonH.export(t, agentExport)
	resp.Body.Close()

	protoH := newHarness(t)
	body, err := proto.Marshal(agentExportProto(t))
	if err != nil {
		t.Fatal(err)
	}
	resp = postProto(t, protoH, body, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("protobuf export: status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-protobuf" {
		t.Errorf("a protobuf export must get a protobuf response, got %q", ct)
	}
	resp.Body.Close()

	a, b := comparable(jsonH.records(t)), comparable(protoH.records(t))
	if len(a) != 3 || len(a) != len(b) {
		t.Fatalf("record counts: json %d, protobuf %d, want 3 each", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("record %d differs by encoding:\n json  %+v\n proto %+v", i, a[i], b[i])
		}
	}
}

// TestGzipProtobufExport covers the OpenTelemetry Collector's otlphttp
// default, which compresses.
func TestGzipProtobufExport(t *testing.T) {
	h := newHarness(t)
	body, _ := proto.Marshal(agentExportProto(t))
	resp := postProto(t, h, body, true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n := len(h.records(t)); n != 3 {
		t.Fatalf("recorded %d spans, want 3", n)
	}
}

// TestDecompressionBombIsRefused: the size limit applies after gzip, or a
// small compressed body could expand without bound.
func TestDecompressionBombIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	sink, err := gwaudit.NewEvidenceSink(gwaudit.EvidenceSinkConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	rec, err := recorder.New(recorder.Config{Sink: sink, Token: testToken, MaxBodyBytes: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{srv: newServer(t, rec.Handler())}

	resp := postProto(t, h, bytes.Repeat([]byte{0}, 1<<22), true) // 4 MiB of zeros, tiny compressed
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for an export that expands past the limit", resp.StatusCode)
	}
}

// TestGRPCExport covers the third transport, and that it enforces the same
// token as HTTP.
func TestGRPCExport(t *testing.T) {
	h := newHarness(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	h.rec.GRPCService().Register(srv)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := coltracepb.NewTraceServiceClient(conn)

	// Without a token: refused.
	_, err = client.Export(context.Background(), agentExportProto(t))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated gRPC export: got %v, want Unauthenticated", err)
	}

	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+testToken)
	resp, err := client.Export(ctx, agentExportProto(t))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if resp.GetPartialSuccess().GetRejectedSpans() != 0 {
		t.Fatalf("rejected spans: %d", resp.GetPartialSuccess().GetRejectedSpans())
	}
	if n := len(h.records(t)); n != 3 {
		t.Fatalf("recorded %d spans over gRPC, want 3", n)
	}
}

// TestUnknownContentTypeIsRefusedWithGuidance keeps the useful half of the old
// protobuf refusal: an encoding we cannot read gets a message naming the ones
// we can.
func TestUnknownContentTypeIsRefusedWithGuidance(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/traces", bytes.NewBufferString("x"))
	req.Header.Set("Content-Type", "text/csv")
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d, want 415", resp.StatusCode)
	}
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	if !bytes.Contains(buf[:n], []byte("application/x-protobuf")) {
		t.Errorf("refusal does not name the accepted encodings: %q", buf[:n])
	}
}

func newServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}
