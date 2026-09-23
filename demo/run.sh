#!/usr/bin/env bash
# End-to-end containment demo.
#
# Stands up a confined agent that has root inside its own sandbox and is
# actively trying to escape, and shows that it cannot -- then kills it, then
# verifies the evidence with nothing but the log file and a public key.
#
# Usage:  ./demo/run.sh [--keep]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$HERE/.work"
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

CONFINED_NET=agw-confined
EGRESS_NET=agw-egress
SUBNET=172.31.99.0/24
PROXY_IP=172.31.99.10
AGENT_IP=172.31.99.20
PROXY=agw-proxy
AGENT=agw-agent

bold()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
info()  { printf '  %s\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }

cleanup() {
    [[ $KEEP -eq 1 ]] && { echo; info "--keep set; leaving containers up"; return; }
    docker rm -f "$AGENT" "$PROXY" >/dev/null 2>&1 || true
    docker network rm "$CONFINED_NET" "$EGRESS_NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
bold "0. Build"
rm -rf "$WORK"; mkdir -p "$WORK/bin" "$WORK/evidence"

ARCH=$(docker version --format '{{.Server.Arch}}')
info "building agw and ags for linux/$ARCH"
( cd "$ROOT" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -o "$WORK/bin/agw" ./cmd/agw )
( cd "$ROOT" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -o "$WORK/bin/ags" ./cmd/ags )

cp "$HERE/Dockerfile.agw" "$WORK/Dockerfile.agw"
cp "$HERE/Dockerfile.agent" "$WORK/Dockerfile.agent"
cp "$HERE/rogue_agent.py" "$WORK/rogue_agent.py"

info "building images"
docker build -q -f "$WORK/Dockerfile.agw"   -t agw-proxy:demo "$WORK" >/dev/null
docker build -q -f "$WORK/Dockerfile.agent" -t agw-agent:demo "$WORK" >/dev/null

info "generating the checkpoint key"
( cd "$ROOT" && go build -o "$WORK/agw-host" ./cmd/agw )
"$WORK/agw-host" keygen \
    --out "$WORK/evidence/checkpoint.key" \
    --pub "$WORK/evidence/checkpoint.pub" | sed 's/^/  /'
chmod 600 "$WORK/evidence/checkpoint.key"

# ---------------------------------------------------------------------------
bold "1. Network"
docker rm -f "$AGENT" "$PROXY" >/dev/null 2>&1 || true
docker network rm "$CONFINED_NET" "$EGRESS_NET" >/dev/null 2>&1 || true

# --internal removes the external route at the Docker level, outside the
# container. A root agent inside cannot restore it: the route does not exist in
# its namespace to be edited, and the NAT rule that would carry it was never
# created on the host.
docker network create --internal --subnet "$SUBNET" "$CONFINED_NET" >/dev/null
docker network create "$EGRESS_NET" >/dev/null
info "$CONFINED_NET  internal, $SUBNET  (the agent's only network)"
info "$EGRESS_NET    has a route out    (proxy only)"

# ---------------------------------------------------------------------------
bold "2. Start the confinement proxy"
docker run -d --name "$PROXY" \
    --network "$CONFINED_NET" --ip "$PROXY_IP" \
    -v "$WORK/evidence:/var/log/agw" \
    -v "$HERE/policy.yaml:/etc/agw/policy.yaml:ro" \
    agw-proxy:demo \
    proxy \
      --policy /etc/agw/policy.yaml \
      --listen 0.0.0.0:8080 \
      --admin /var/run/agw/admin.sock \
      --evidence /var/log/agw/evidence.jsonl \
      --key /var/log/agw/checkpoint.key \
      --checkpoint-every 10 \
      --workload "agent-eval-01=$AGENT_IP" >/dev/null

docker network connect "$EGRESS_NET" "$PROXY"
info "proxy is on both networks; the agent is on only one"
sleep 2

# ---------------------------------------------------------------------------
bold "3. Release the agent (root inside its sandbox, actively hostile)"
docker run -d --name "$AGENT" \
    --network "$CONFINED_NET" --ip "$AGENT_IP" \
    --cap-add NET_ADMIN \
    -e "AGW_PROXY=http://$PROXY_IP:8080" \
    agw-agent:demo >/dev/null

info "NET_ADMIN granted deliberately -- it should not help"
echo
docker logs -f "$AGENT" 2>&1 &
LOGS=$!

# Let the escape attempts run before firing the kill switch. If the agent
# died, say so rather than reporting a kill switch that had nothing to kill.
sleep 38
if [ "$(docker inspect -f '{{.State.Running}}' "$AGENT" 2>/dev/null)" != "true" ]; then
    kill $LOGS 2>/dev/null || true
    red "the agent exited before the kill switch could fire -- see its output above"
    docker logs --tail 20 "$AGENT" 2>&1 | sed 's/^/  /'
    exit 1
fi

# ---------------------------------------------------------------------------
bold "4. Fire the kill switch"
docker exec "$PROXY" agw revoke \
    --admin /var/run/agw/admin.sock \
    --workload agent-eval-01 \
    --reason "demo: operator cut the agent off" 2>&1 | sed 's/^/  /'

sleep 12
kill $LOGS 2>/dev/null || true
wait $LOGS 2>/dev/null || true

# ---------------------------------------------------------------------------
bold "5. What the agent achieved"
docker exec "$PROXY" agw status --admin /var/run/agw/admin.sock 2>&1 | sed 's/^/  /'

# ---------------------------------------------------------------------------
bold "6. Verify the evidence -- file and public key only"
docker stop "$PROXY" >/dev/null 2>&1 || true
sleep 2

info "the verifier runs on the host, against the file, with no access to anything"
( cd "$ROOT" && go run ./cmd/agw audit verify "$WORK/evidence/evidence.jsonl" \
    --key "$WORK/evidence/checkpoint.pub" ) 2>&1 | sed 's/^/  /'
info "and so does the independent verifier, which shares no code with the writer"
( cd "$ROOT" && go run ./cmd/agw-verify --key "$WORK/evidence/checkpoint.pub" \
    "$WORK/evidence/evidence.jsonl" ) 2>&1 | tail -1 | sed 's/^/  /'

bold "7. What the agent tried, from the chain"
( cd "$ROOT" && go run ./cmd/agw audit show "$WORK/evidence/evidence.jsonl" ) 2>&1 | sed 's/^/  /' | head -45

bold "Evidence"
info "log         $WORK/evidence/evidence.jsonl"
info "public key  $WORK/evidence/checkpoint.pub"
echo
green "Anyone can verify that log with those two files and nothing else."
