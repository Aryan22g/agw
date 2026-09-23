// Package recorder turns telemetry an agent already emits into signed,
// hash-linked evidence.
//
// This is the lowest rung of the adoption ladder, and the one everything else
// depends on:
// nobody deploys a containment layer on day one, but they will point an
// existing OpenTelemetry exporter at a port and get a compliance artifact for
// it. Once we are the record of what agents did, becoming the control over
// what they may do is an upgrade rather than a migration.
//
// What this does NOT do, and the docs must keep saying so: it records what the
// agent REPORTS. A compromised agent lies, and nothing here can tell. That is
// the difference between this and internal/confine, where the record is made
// at a point the workload cannot bypass. Level 0 is compliance; Level 3 is
// defence.
package recorder

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// OTLP JSON payloads. Only the fields that carry meaning for an evidence
// record are modelled -- the rest of the schema is skipped rather than
// half-parsed, so a change upstream cannot silently alter what we record.
type otlpPayload struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []otlpAttr `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Spans []otlpSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type otlpSpan struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	Name              string     `json:"name"`
	Kind              int        `json:"kind"`
	StartTimeUnixNano any        `json:"startTimeUnixNano"`
	EndTimeUnixNano   any        `json:"endTimeUnixNano"`
	Attributes        []otlpAttr `json:"attributes"`
	Status            struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
}

type otlpAttr struct {
	Key   string `json:"key"`
	Value struct {
		StringValue *string  `json:"stringValue"`
		IntValue    any      `json:"intValue"`
		BoolValue   *bool    `json:"boolValue"`
		DoubleValue *float64 `json:"doubleValue"`
	} `json:"value"`
}

func (a otlpAttr) str() string {
	switch {
	case a.Value.StringValue != nil:
		return *a.Value.StringValue
	case a.Value.BoolValue != nil:
		return strconv.FormatBool(*a.Value.BoolValue)
	case a.Value.IntValue != nil:
		return anyToString(a.Value.IntValue)
	case a.Value.DoubleValue != nil:
		return strconv.FormatFloat(*a.Value.DoubleValue, 'f', -1, 64)
	}
	return ""
}

// anyToString handles protobuf's JSON mapping for 64-bit integers, which are
// encoded as strings to survive JavaScript's number precision, but which some
// exporters emit as numbers anyway.
func anyToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func attrMap(attrs []otlpAttr) map[string]string {
	out := make(map[string]string, len(attrs))
	for _, a := range attrs {
		if a.Key == "" {
			continue
		}
		out[a.Key] = a.str()
	}
	return out
}

// firstOf returns the first non-empty value among the given keys, so one
// mapping can accept several generations of semantic convention without
// guessing which the exporter used.
func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

func unixNano(v any) time.Time {
	s := anyToString(v)
	if s == "" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// decodeID accepts both spellings of a trace or span id.
//
// The OpenTelemetry specification says hex for OTLP/JSON; protobuf's own JSON
// mapping says base64 for bytes fields, and exporters exist that follow each.
// Accepting both is the difference between working with a user's existing
// pipeline and telling them their exporter is wrong.
func decodeID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if _, err := hex.DecodeString(s); err == nil {
		return strings.ToLower(s)
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return hex.EncodeToString(raw)
	}
	return s
}
