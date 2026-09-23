package recorder

import (
	"context"
	"encoding/hex"
	"strconv"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fromProto converts a protobuf export into the same shape the JSON path
// decodes into, so there is exactly one span mapping and one ingest path.
//
// Converting at the edge is deliberate. Two mappings -- one per encoding --
// would drift, and the first sign would be the same agent action producing
// different evidence depending on which exporter setting a team happened to
// leave on.
func fromProto(req *coltracepb.ExportTraceServiceRequest) otlpPayload {
	var out otlpPayload
	for _, rs := range req.GetResourceSpans() {
		var r struct {
			Resource struct {
				Attributes []otlpAttr `json:"attributes"`
			} `json:"resource"`
			ScopeSpans []struct {
				Spans []otlpSpan `json:"spans"`
			} `json:"scopeSpans"`
		}
		r.Resource.Attributes = protoAttrs(rs.GetResource().GetAttributes())

		for _, ss := range rs.GetScopeSpans() {
			var scope struct {
				Spans []otlpSpan `json:"spans"`
			}
			for _, sp := range ss.GetSpans() {
				span := otlpSpan{
					// The JSON mapping carries ids as hex; producing hex here
					// means decodeID sees the same thing either way.
					TraceID:           hex.EncodeToString(sp.GetTraceId()),
					SpanID:            hex.EncodeToString(sp.GetSpanId()),
					Name:              sp.GetName(),
					Kind:              int(sp.GetKind()),
					StartTimeUnixNano: strconv.FormatUint(sp.GetStartTimeUnixNano(), 10),
					EndTimeUnixNano:   strconv.FormatUint(sp.GetEndTimeUnixNano(), 10),
					Attributes:        protoAttrs(sp.GetAttributes()),
				}
				span.Status.Code = int(sp.GetStatus().GetCode())
				span.Status.Message = sp.GetStatus().GetMessage()
				scope.Spans = append(scope.Spans, span)
			}
			r.ScopeSpans = append(r.ScopeSpans, scope)
		}
		out.ResourceSpans = append(out.ResourceSpans, r)
	}
	return out
}

func protoAttrs(kvs []*commonpb.KeyValue) []otlpAttr {
	out := make([]otlpAttr, 0, len(kvs))
	for _, kv := range kvs {
		a := otlpAttr{Key: kv.GetKey()}
		v := kv.GetValue()
		switch x := v.GetValue().(type) {
		case *commonpb.AnyValue_StringValue:
			s := x.StringValue
			a.Value.StringValue = &s
		case *commonpb.AnyValue_BoolValue:
			b := x.BoolValue
			a.Value.BoolValue = &b
		case *commonpb.AnyValue_IntValue:
			a.Value.IntValue = strconv.FormatInt(x.IntValue, 10)
		case *commonpb.AnyValue_DoubleValue:
			d := x.DoubleValue
			a.Value.DoubleValue = &d
		default:
			// Arrays, maps and bytes carry nothing the evidence record
			// uses. Skipping them keeps an unfamiliar attribute from being
			// half-rendered into a field someone later relies on.
			continue
		}
		out = append(out, a)
	}
	return out
}

// GRPCService implements the OTLP/gRPC trace service on top of the same
// ingest path as the HTTP handler.
type GRPCService struct {
	coltracepb.UnimplementedTraceServiceServer
	r *Receiver
}

// GRPCService returns the gRPC trace service for this receiver.
func (r *Receiver) GRPCService() *GRPCService { return &GRPCService{r: r} }

// Register attaches the trace service to a gRPC server.
func (g *GRPCService) Register(s *grpc.Server) { coltracepb.RegisterTraceServiceServer(s, g) }

// Export records one batch. Authentication uses the same bearer token as
// HTTP, carried in the "authorization" metadata key, which is where
// OTEL_EXPORTER_OTLP_HEADERS puts it for a gRPC exporter.
func (g *GRPCService) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	if !g.authorizedGRPC(ctx) {
		g.r.rejected.Add(1)
		return nil, status.Error(codes.Unauthenticated, "a valid bearer token is required")
	}

	_, failed := g.r.ingest(ctx, fromProto(req))

	resp := &coltracepb.ExportTraceServiceResponse{}
	if failed > 0 {
		resp.PartialSuccess = &coltracepb.ExportTracePartialSuccess{
			RejectedSpans: int64(failed),
			ErrorMessage:  "evidence sink rejected these spans",
		}
	}
	return resp, nil
}

func (g *GRPCService) authorizedGRPC(ctx context.Context) bool {
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return g.r.checkBearer("")
	}
	return g.r.checkBearer(vals[0])
}
