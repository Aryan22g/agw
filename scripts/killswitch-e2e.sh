#!/usr/bin/env bash
# The kill switch, end to end, with its latency asserted. "We have a kill
# switch" is worth nothing without a number.
#
# A contained workload keeps making requests and spawns a child; `agw suspend`
# from another process must cut its connections within the bound, kill its
# whole process group, and leave the event in evidence that verifies.
#
# Linux, root, iproute2 and nftables. Run by CI's root job and `make test-linux`.
set -euo pipefail
BOUND_MS=${AGW_KILL_BOUND_MS:-100}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d)"; cd "$W"
export AGW_HOME="$W/home"
SOCK="$W/admin.sock"
fail() { echo "FAIL: $*"; cat run.log 2>/dev/null | tail -20; exit 1; }

go build -C "$ROOT" -o "$W/agw" ./cmd/agw
AGW="$W/agw"
$AGW init . >/dev/null
sed -i 's/id: my-agent/id: agent/' agw-policy.yaml

$AGW run --policy agw-policy.yaml --workload agent --evidence r.jsonl --admin "$SOCK" -- \
  sh -c 'sleep 1000 & while true; do curl -s -o /dev/null --max-time 5 https://pypi.org/simple/; sleep 0.3; done' \
  >run.log 2>&1 &
RUN=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || fail "agw run never opened its admin socket"
sleep 2

# A second agw must not take over a live admin socket.
if $AGW proxy --policy agw-policy.yaml --listen 127.0.0.1:1 --evidence x.jsonl --admin "$SOCK" 2>err.txt; then
  fail "a second agw took over a live admin socket"
fi
grep -q "in use by another agw" err.txt || fail "unexpected error: $(cat err.txt)"

out=$($AGW suspend --workload agent --admin "$SOCK" --reason "kill switch test")
echo "$out"
wait "$RUN" || true

teardown=$(echo "$out" | awk '/teardown/ {print $2}')
ms=$(python3 -c "
import re,sys
s='$teardown'; m=re.match(r'([0-9.]+)(ns|µs|us|ms|s)$', s)
if not m: sys.exit('unparseable teardown: '+s)
v=float(m.group(1)); print(v*{'ns':1e-6,'µs':1e-3,'us':1e-3,'ms':1,'s':1000}[m.group(2)])")
python3 -c "import sys; sys.exit(0 if $ms <= $BOUND_MS else 1)" \
  || fail "connection teardown took ${ms}ms, bound is ${BOUND_MS}ms"
echo "teardown ${ms}ms (bound ${BOUND_MS}ms)"

pgrep -f "sleep 1000" >/dev/null && fail "the workload's child survived the kill switch"
grep -q "suspended by the kill switch" run.log || fail "agw run did not report the suspension"

$AGW audit verify r.jsonl --key home/checkpoint.key.pub --quiet || fail "evidence did not verify"
$AGW audit show r.jsonl --action workload.revoke --json | grep -q "workload_killed=true" \
  || fail "the revocation and the kill are not in the evidence"
echo "kill switch: connections cut, process group killed, recorded, verified"
rm -rf "$W"
