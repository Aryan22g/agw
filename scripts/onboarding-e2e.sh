#!/usr/bin/env bash
# The first ten minutes, as a new user meets them, run as a test.
#
# Every command here is one the documentation tells people to type. If any of
# them stops working, this fails -- which is the point: before this script
# existed, the verify command `agw` printed for its own users did not run, and
# nothing noticed.
#
# Needs: Go, Python 3 with opentelemetry-sdk and the otlp-proto-http and
# otlp-proto-grpc exporters.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill "${WATCH_PID:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
cd "$WORK"

export AGW_HOME="$WORK/home"
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1"; exit 1; }

go build -C "$ROOT" -o "$WORK/agw" ./cmd/agw
go build -C "$ROOT" -o "$WORK/agw-verify" ./cmd/agw-verify
AGW="$WORK/agw"

step "agw init"
$AGW init . | tee init.out
[ -f agw-policy.yaml ] || fail "init wrote no policy"
[ -f home/checkpoint.key.pub ] || fail "init made no key"
$AGW policy lint agw-policy.yaml

step "agw watch, fed by the stock OpenTelemetry Python SDK"
$AGW watch --out ev.jsonl --token tok --policy agw-policy.yaml \
    --listen 127.0.0.1:14318 --grpc-listen 127.0.0.1:14317 2>watch.log &
WATCH_PID=$!
for _ in $(seq 1 50); do curl -sf http://127.0.0.1:14318/healthz >/dev/null && break; sleep 0.1; done

cat > agent.py <<'PY'
import os, sys
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
if os.environ["OTEL_EXPORTER_OTLP_PROTOCOL"] == "grpc":
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
else:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
p = TracerProvider(resource=Resource.create({"service.name": sys.argv[1]}))
p.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
t = p.get_tracer("agent")
for url, host in [("https://pypi.org/simple/", "pypi.org"), ("http://169.254.169.254/latest/", "169.254.169.254")]:
    with t.start_as_current_span("GET") as s:
        s.set_attribute("http.request.method", "GET"); s.set_attribute("url.full", url); s.set_attribute("server.address", host)
p.shutdown()
PY
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer tok"
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:14318 OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf python3 agent.py my-agent
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:14317 OTEL_EXPORTER_OTLP_PROTOCOL=grpc python3 agent.py my-agent
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:14318 OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer wrong" \
    OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf python3 agent.py intruder 2>/dev/null || true
kill -INT "$WATCH_PID"; wait "$WATCH_PID" || true
cat watch.log
grep -q "4 spans seen, 4 recorded, 1 exports rejected" watch.log || fail "expected 4 recorded spans and 1 rejected export"

step "the verify command watch printed, run exactly as printed"
HINT=$(grep -o 'verify with  .*' watch.log | sed 's/verify with  //')
[ -n "$HINT" ] || fail "watch printed no verify command"
eval "$WORK/$HINT"

step "the independent verifier agrees"
"$WORK/agw-verify" --key home/checkpoint.key.pub ev.jsonl

step "shadow mode found the metadata probe"
$AGW audit show ev.jsonl --would-deny | tee shadow.out
grep -q metadata_endpoint shadow.out || fail "the IMDS probe was not flagged"

step "draft a policy from what was observed"
$AGW policy suggest ev.jsonl --workload my-agent --out drafted.yaml
$AGW policy lint drafted.yaml
grep -q "host: pypi.org" drafted.yaml || fail "pypi.org not drafted"
if grep -q "host: 169.254.169.254" drafted.yaml; then fail "the metadata endpoint was drafted as allowed"; fi

step "explain a decision"
$AGW policy explain --policy drafted.yaml --workload my-agent 169.254.169.254:80 | tee explain.out
grep -q metadata_endpoint explain.out || fail "explain did not name the structural denial"

step "tampering is detected and exits 2"
sed 's/"Decision":"would_deny"/"Decision":"allow"/' ev.jsonl > tampered.jsonl
set +e; $AGW audit verify tampered.jsonl --key home/checkpoint.key.pub --quiet; code=$?; set -e
[ "$code" = 2 ] || fail "tampered evidence exited $code, want 2"

step "export for an auditor, and as IETF agent-audit-trail records"
$AGW audit export ev.jsonl --key home/checkpoint.key.pub --out bundle.json
$AGW audit verify-bundle bundle.json --key home/checkpoint.key.pub
$AGW audit export ev.jsonl --key home/checkpoint.key.pub --format aat --out ev.aat.jsonl
set +e; $AGW audit export tampered.jsonl --key home/checkpoint.key.pub --format aat --out bad.aat; code=$?; set -e
[ "$code" = 2 ] && [ ! -e bad.aat ] || fail "a tampered chain was converted"

printf '\n\033[32mOnboarding path works end to end.\033[0m\n'
