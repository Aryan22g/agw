package recorder

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	gwaudit "github.com/Aryan22g/agw/internal/gateway/audit"
)

// Sink records observations. Satisfied by *audit.EvidenceSink.
type Sink interface {
	Write(ctx context.Context, eventName string, ev gwaudit.GatewayEvent) (gwaudit.Record, error)
}

// Config configures the receiver.
type Config struct {
	Sink   Sink
	Logger *slog.Logger

	// Evaluator turns the recorder into shadow mode: every observation is
	// checked against egress policy and the verdict recorded, but nothing is
	// blocked. Optional; nil records observations without a verdict.
	Evaluator *Evaluator

	// MaxBodyBytes bounds a single export. OTLP batches are small; the limit
	// is there so an exporter pointed at the wrong port cannot exhaust memory.
	MaxBodyBytes int64

	// Token is a bearer token every export must present.
	//
	// Without one, anything that can reach this port can append records. They
	// cannot alter history -- the chain prevents that -- but they can add to
	// it, and the producer's next signed checkpoint then covers the injected
	// records as readily as its own. The producer signs them without knowing.
	//
	// Required unless AllowUnauthenticated is set, because "the recorder was
	// on loopback" is a deployment assumption, not a control.
	Token string

	// AllowUnauthenticated runs without a token. For a single-user machine
	// where the operator has decided the exposure is acceptable; it is never
	// the default.
	AllowUnauthenticated bool
}

// Receiver accepts OTLP trace exports and writes them to the chain.
//
// Every standard OTLP transport is accepted -- HTTP with a JSON or protobuf
// body, optionally gzipped, and gRPC -- so an exporter left on its defaults
// works. Five minutes is the entire premise of this rung, and the fastest
// five minutes is the one where the user changes one environment variable and
// nothing else.
type Receiver struct {
	cfg Config
	log *slog.Logger

	spans    atomic.Uint64
	recorded atomic.Uint64
	rejected atomic.Uint64

	wouldAllow   atomic.Uint64
	wouldDeny    atomic.Uint64
	notEvaluable atomic.Uint64
}

// Shadow reports what egress policy would have done. Zero unless an Evaluator
// is configured.
func (r *Receiver) Shadow() ShadowCounts {
	return ShadowCounts{
		WouldAllow:   r.wouldAllow.Load(),
		WouldDeny:    r.wouldDeny.Load(),
		NotEvaluable: r.notEvaluable.Load(),
	}
}

// New builds a Receiver.
func New(cfg Config) (*Receiver, error) {
	if cfg.Sink == nil {
		return nil, errors.New("recorder: an evidence sink is required")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 4 << 20
	}
	if cfg.Token == "" && !cfg.AllowUnauthenticated {
		return nil, errors.New(
			"recorder: a token is required, or AllowUnauthenticated must be set explicitly; " +
				"an unauthenticated recorder lets anything that reaches it append records " +
				"that the next signed checkpoint will then vouch for")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Receiver{cfg: cfg, log: log}, nil
}

// Stats reports spans seen, records written, and exports rejected.
func (r *Receiver) Stats() (spans, recorded, rejected uint64) {
	return r.spans.Load(), r.recorded.Load(), r.rejected.Load()
}

// Handler returns the HTTP handler. /v1/traces is the OTLP path.
func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/traces", r.handleTraces)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func (r *Receiver) handleTraces(w http.ResponseWriter, req *http.Request) {
	if !r.authorized(req) {
		r.rejected.Add(1)
		r.log.Warn("rejected an unauthenticated export",
			slog.String("remote", req.RemoteAddr))
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := readBody(w, req, r.cfg.MaxBodyBytes)
	if err != nil {
		r.rejected.Add(1)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// All three OTLP encodings are accepted, and all three land in the same
	// ingest path. An earlier version took JSON only, on the reasoning that
	// a protobuf toolchain is not a five-minute setup -- but that was the
	// wrong party's toolchain. The exporter already has one: http/protobuf is
	// the default in most SDKs, and the Python SDK, which is what most agent
	// code is written in, cannot emit JSON at all. Refusing protobuf meant
	// Level 0 needed a Collector in front of it for the majority of users.
	ct := req.Header.Get("Content-Type")
	switch {
	case isProtobuf(ct):
		var pb coltracepb.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &pb); err != nil {
			r.rejected.Add(1)
			http.Error(w, "malformed OTLP protobuf payload", http.StatusBadRequest)
			return
		}
		written, failed := r.ingest(req.Context(), fromProto(&pb))
		r.log.Debug("export recorded", slog.Int("written", written), slog.Int("failed", failed))
		resp := &coltracepb.ExportTraceServiceResponse{}
		if failed > 0 {
			resp.PartialSuccess = &coltracepb.ExportTracePartialSuccess{
				RejectedSpans: int64(failed),
				ErrorMessage:  "evidence sink rejected these spans",
			}
		}
		out, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
		return

	case ct == "" || isJSON(ct):
		// fall through to JSON below

	default:
		r.rejected.Add(1)
		http.Error(w,
			"unsupported Content-Type "+ct+"; this receiver accepts application/json "+
				"and application/x-protobuf (OTLP/HTTP), or OTLP/gRPC on the gRPC port",
			http.StatusUnsupportedMediaType)
		return
	}

	var payload otlpPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		r.rejected.Add(1)
		http.Error(w, "malformed OTLP payload", http.StatusBadRequest)
		return
	}

	_, failed := r.ingest(req.Context(), payload)

	w.Header().Set("Content-Type", "application/json")

	if failed > 0 {
		// OTLP's partial success is the honest answer: the exporter is told
		// exactly how many spans did not make it, so a full evidence disk
		// surfaces at the sender instead of silently losing records.
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"partialSuccess": map[string]any{
				"rejectedSpans": fmt.Sprintf("%d", failed),
				"errorMessage":  "evidence sink rejected these spans",
			},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"partialSuccess":{}}`))
}

// ingest maps every span in an export to an observation, evaluates it against
// policy if one is configured, and writes it to the chain. It is the single
// path every transport uses, so a span means the same thing whichever way it
// arrived.
func (r *Receiver) ingest(ctx context.Context, payload otlpPayload) (written, failed int) {
	for _, rs := range payload.ResourceSpans {
		resource := attrMap(rs.Resource.Attributes)
		for _, ss := range rs.ScopeSpans {
			for _, span := range ss.Spans {
				r.spans.Add(1)

				obs := mapSpan(span, resource)
				ev := obs.toEvent()

				if r.cfg.Evaluator != nil {
					verdict, reason := r.cfg.Evaluator.Evaluate(obs)
					// The verdict replaces the observed outcome in Decision
					// so `agw audit show --decision would_deny` surfaces
					// them with no new filter. The span's own status is kept
					// in ResourceType, which would otherwise just say
					// "observed".
					ev.ResourceType = "observed:" + obs.Outcome
					ev.Decision = verdict
					ev.ReasonCode = reason

					switch verdict {
					case VerdictWouldAllow:
						r.wouldAllow.Add(1)
					case VerdictWouldDeny:
						r.wouldDeny.Add(1)
						r.log.Warn("policy would have denied this",
							slog.String("agent", obs.AgentID),
							slog.String("action", obs.Action),
							slog.String("destination", obs.Target),
							slog.String("reason", reason))
					default:
						r.notEvaluable.Add(1)
					}
				}

				if _, err := r.cfg.Sink.Write(ctx, EventAgentActivity, ev); err != nil {
					failed++
					r.log.Error("could not record span",
						slog.String("agent", obs.AgentID),
						slog.String("action", obs.Action),
						slog.Any("error", err))
					continue
				}
				written++
				r.recorded.Add(1)
			}
		}
	}
	return written, failed
}

// readBody reads an export, undoing gzip if the exporter compressed it.
//
// Compression is the Collector's default for otlphttp and an option in every
// SDK, and a receiver that rejected it would be one more thing to configure
// before the five minutes are up. The limit applies to the DECOMPRESSED size,
// because a limit on the wire size alone is a decompression bomb waiting to
// happen.
func readBody(w http.ResponseWriter, req *http.Request, limit int64) ([]byte, error) {
	var rd io.Reader = http.MaxBytesReader(w, req.Body, limit)
	switch strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(rd)
		if err != nil {
			return nil, errors.New("malformed gzip body")
		}
		defer gz.Close()
		rd = gz
	default:
		return nil, errors.New("unsupported Content-Encoding; use gzip or none")
	}

	body, err := io.ReadAll(io.LimitReader(rd, limit+1))
	if err != nil {
		return nil, errors.New("export body could not be read")
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("export exceeds %d bytes after decompression", limit)
	}
	return body, nil
}

// authorized checks the bearer token in constant time.
//
// A timing side channel here would let a caller that can reach the port
// recover the token a byte at a time, which is the whole of the control.
func (r *Receiver) authorized(req *http.Request) bool {
	return r.checkBearer(req.Header.Get("Authorization"))
}

// checkBearer validates an Authorization value, shared by HTTP and gRPC so
// the two transports cannot disagree about who is allowed to write.
func (r *Receiver) checkBearer(h string) bool {
	if r.cfg.Token == "" {
		return r.cfg.AllowUnauthenticated
	}

	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(r.cfg.Token)) == 1
}

func isProtobuf(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.HasPrefix(ct, "application/x-protobuf") || strings.HasPrefix(ct, "application/protobuf")
}

func isJSON(contentType string) bool {
	for _, ok := range []string{"application/json", "application/x-ndjson"} {
		if len(contentType) >= len(ok) && contentType[:len(ok)] == ok {
			return true
		}
	}
	return false
}
