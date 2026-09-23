#!/usr/bin/env bash
# Prove the sidecar confines an agent that has root and is trying to leave.
# Uses compose.yaml exactly as shipped, with the attacker as the agent.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
fail() { echo "FAIL: $*"; docker compose -p agwsctest logs agw | tail -20; exit 1; }
trap 'docker compose -p agwsctest down -v >/dev/null 2>&1 || true' EXIT

docker build -q -f "$ROOT/Dockerfile.agw" -t agw:sidecar-test "$ROOT" >/dev/null
docker build -q -f Dockerfile.attacker -t agw-attacker:test . >/dev/null
export AGW_IMAGE=agw:sidecar-test AGENT_IMAGE=agw-attacker:test

# Control: before sidecar-init, the same direct request must SUCCEED.
# Otherwise "blocked" below would only mean this host has no network, and the
# test would prove nothing about the rule.
docker compose -p agwsctest up -d agw >/dev/null 2>&1
ctl=$(docker compose -p agwsctest run --rm --no-deps -T --user 0 --entrypoint sh agent \
      -c "curl -s -o /dev/null -w '%{http_code}' --noproxy '*' --max-time 8 https://pypi.org/" 2>/dev/null || true)
[ "$ctl" = 200 ] || fail "control: direct egress before sidecar-init returned '$ctl', want 200 (no network on this host?)"
echo "control: direct egress works before sidecar-init ($ctl)"

docker compose -p agwsctest up -d agw-init >/dev/null 2>&1
code=$(docker wait "$(docker compose -p agwsctest ps -a -q agw-init)")
[ "$code" = 0 ] || fail "sidecar-init exited $code"
out=$(docker compose -p agwsctest run --rm --no-deps -T --user 0 agent sh /attack.sh)
echo "$out"

check() { echo "$out" | grep -E "^$1 +$2\$" >/dev/null || fail "$1: expected $2"; }
check "whoami"                   "0"
check "via proxy: pypi.org"      "200"
check "via proxy: example.com"   "(403|blocked)"
check "via proxy: metadata"      "403"
check "direct: pypi.org"         "blocked"
check "direct: metadata"         "blocked"
check "direct: dns to 1.1.1.1"   "blocked"
check "loopback: other port"     "blocked"
check "remove the firewall"      "refused"
check "become the proxy uid"     "refused"

docker compose -p agwsctest stop agw >/dev/null 2>&1
docker compose -p agwsctest run --rm --no-deps -T --entrypoint sh agw -c \
  'agw audit verify /evidence/evidence.jsonl --key /evidence/.agw/checkpoint.key.pub --quiet && agw audit show /evidence/evidence.jsonl' \
  || fail "evidence did not verify"
echo "sidecar confinement holds: root in the agent container, and every way out is refused or recorded"
