#!/usr/bin/env bash
# Contained mode: run the gym where the agent genuinely has no route out.
#
# Hosted mode (`agw-gym run`) links the enforcement code into the test process.
# That buys precision -- it can make the evidence sink fail on command, revoke a
# workload through the registry, and answer DNS with a rebinding -- but it
# cannot establish the one property the architecture rests on: that a workload
# which has decided not to cooperate has nowhere else to send its packets.
#
# Here that property is real. The agent runs in a container on a Docker network
# created with --internal, attached to nothing but the proxy. Nothing in this
# repository enforces it, which is exactly the point: the containment boundary
# is the network, and the network is not ours to subvert.
#
# The three roles are in three containers on purpose. The world keeps its own
# receipt log of every request it served; the proxy writes the evidence chain;
# the agent reports what it managed to do. Scoring compares them, and trusts
# none of them about the others.
#
# Usage:  ./gym/contained.sh [--seed N] [--keep]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$HERE/.work"

SEED=${GYM_SEED:-$((RANDOM * RANDOM % 900000 + 1000))}
KEEP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --seed) SEED="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

CONFINED_NET=agwgym-confined
EGRESS_NET=agwgym-egress
CONFINED_SUBNET=172.31.98.0/24
EGRESS_SUBNET=172.31.99.0/24
PROXY_CONFINED_IP=172.31.98.10
AGENT_IP=172.31.98.20
PROXY_EGRESS_IP=172.31.99.10
WORLD_IP=172.31.99.30
PROXY_PORT=8080
CONTROL_PORT=9900
WORKLOAD=agent-eval-01

PROXY=agwgym-proxy
WORLD=agwgym-world
AGENT=agwgym-agent

bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }
info() { printf '  %s\n' "$1"; }
fail() { printf '\033[31m%s\033[0m\n' "$1"; }

cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        echo; info "--keep set; containers and networks left up"
        info "world ledger:  curl -s http://127.0.0.1:${CONTROL_PORT}/gym/ledger"
        return
    fi
    docker rm -f "$AGENT" "$WORLD" "$PROXY" >/dev/null 2>&1 || true
    docker network rm "$CONFINED_NET" "$EGRESS_NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
bold "0. Build"
rm -rf "$WORK"; mkdir -p "$WORK/bin" "$WORK/evidence" "$WORK/conf"

ARCH=$(docker version --format '{{.Server.Arch}}')
info "building agw, ags and agw-gym for linux/$ARCH"
( cd "$ROOT" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -trimpath -o "$WORK/bin/agw"     ./cmd/agw )
( cd "$ROOT" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -trimpath -o "$WORK/bin/ags"     ./cmd/ags )
( cd "$ROOT" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go build -trimpath -o "$WORK/bin/agw-gym" ./cmd/agw-gym )

# The host build is what scores the run, because scoring must not depend on
# anything inside the containers being alive when it happens.
( cd "$ROOT" && go build -trimpath -o "$WORK/bin/agw-gym-host" ./cmd/agw-gym )

info "seed $SEED"

# ---------------------------------------------------------------------------
bold "1. Generate the world's policy and name mappings"
#
# Both are derived from the seed, on the host, before any container starts --
# the proxy needs its policy at startup, and it resolves world hostnames
# through the system resolver, which is what a real deployment does.
"$WORK/bin/agw-gym-host" world --seed "$SEED" --workload "$WORKLOAD" \
    --subnet "$EGRESS_SUBNET" \
    --write-policy "$WORK/conf/policy.yaml" >/dev/null
"$WORK/bin/agw-gym-host" world --seed "$SEED" --workload "$WORKLOAD" \
    --subnet "$EGRESS_SUBNET" \
    --write-hosts "$WORK/conf/hosts" --world-addr "$WORLD_IP" >/dev/null

info "policy: $(grep -c 'host:' "$WORK/conf/policy.yaml") permitted destinations"
info "hosts:  $(wc -l < "$WORK/conf/hosts" | tr -d ' ') world names -> $WORLD_IP"

info "generating the checkpoint signing key"
( cd "$ROOT" && go run ./cmd/agw keygen --out "$WORK/conf/checkpoint.key" \
    --pub "$WORK/conf/checkpoint.pub" >/dev/null )
# The key is mounted read-only into the proxy, and the signer refuses a key
# other local users can read -- so the mode matters even here.
chmod 600 "$WORK/conf/checkpoint.key"

# ---------------------------------------------------------------------------
bold "2. Build the containment boundary"
#
# --internal is what makes this real: Docker installs no default route on that
# network, so a container attached only to it cannot reach the host, the
# internet, or the other Docker network. The agent's only neighbour is the
# proxy.
docker network rm "$CONFINED_NET" "$EGRESS_NET" >/dev/null 2>&1 || true
docker network create --internal --subnet "$CONFINED_SUBNET" "$CONFINED_NET" >/dev/null
docker network create            --subnet "$EGRESS_SUBNET"   "$EGRESS_NET"   >/dev/null
info "confined $CONFINED_SUBNET (no route anywhere), egress $EGRESS_SUBNET"

docker build -q -t agwgym-base -f "$HERE/Dockerfile" "$WORK" >/dev/null
info "image built"

# ---------------------------------------------------------------------------
bold "3. Start the world"
docker run -d --name "$WORLD" \
    --network "$EGRESS_NET" --ip "$WORLD_IP" \
    -p "127.0.0.1:${CONTROL_PORT}:${CONTROL_PORT}" \
    agwgym-base \
    /bin/agw-gym world --seed "$SEED" --workload "$WORKLOAD" \
        --bind 0.0.0.0 --control "0.0.0.0:${CONTROL_PORT}" >/dev/null

for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${CONTROL_PORT}/gym/health" >/dev/null 2>&1; then break; fi
    sleep 0.25
done
info "$(curl -s "http://127.0.0.1:${CONTROL_PORT}/gym/health")"

# ---------------------------------------------------------------------------
bold "4. Start the enforcement point"
#
# The proxy is the only container on both networks. The workload is registered
# by its source ADDRESS -- nothing the agent can send changes who the proxy
# thinks it is talking to.
# The world's names are appended to /etc/hosts at startup rather than passed
# with --add-host, because there is one line per service and the list is
# generated. The proxy then resolves them through the system resolver, which
# is what it does in production: the containment boundary is the network, not
# the name service.
docker run -d --name "$PROXY" \
    --network "$CONFINED_NET" --ip "$PROXY_CONFINED_IP" \
    -v "$WORK/conf:/conf:ro" -v "$WORK/evidence:/evidence" \
    agwgym-base \
    /bin/sh -c "cat /conf/hosts >> /etc/hosts && exec /bin/agw proxy \
        --policy /conf/policy.yaml \
        --listen 0.0.0.0:${PROXY_PORT} \
        --admin /tmp/admin.sock \
        --evidence /evidence/chain.jsonl \
        --key /conf/checkpoint.key \
        --workload ${WORKLOAD}=${AGENT_IP}" >/dev/null

docker network connect --ip "$PROXY_EGRESS_IP" "$EGRESS_NET" "$PROXY" >/dev/null
sleep 1.5

if ! docker ps --format '{{.Names}}' | grep -q "^${PROXY}$"; then
    fail "the proxy did not stay up:"
    docker logs "$PROXY" 2>&1 | tail -20
    exit 1
fi
info "proxy on $PROXY_CONFINED_IP:${PROXY_PORT} (confined) and $PROXY_EGRESS_IP (egress)"
info "workload $WORKLOAD attested at $AGENT_IP"

# ---------------------------------------------------------------------------
bold "5. Release the agent"
#
# One network, no default route, one neighbour. Everything it manages to do
# from here, it did through the enforcement point -- or the boundary leaked,
# which is what the network_boundary episodes are there to find out.
# The agent gets the same name mappings as the proxy. That is deliberate: a
# direct-route probe must fail because there is no route, not because the name
# did not resolve. Those are different findings and the report has to be able
# to tell them apart.
docker run --rm --name "$AGENT" \
    --network "$CONFINED_NET" --ip "$AGENT_IP" \
    -v "$WORK/conf:/conf:ro" -v "$WORK/evidence:/out" \
    agwgym-base \
    /bin/sh -c "cat /conf/hosts >> /etc/hosts && exec /bin/agw-gym agent \
        --seed ${SEED} --workload ${WORKLOAD} \
        --proxy ${PROXY_CONFINED_IP}:${PROXY_PORT} \
        --out /out/results.json" \
    || info "agent exited non-zero (episodes failed; the report says which)"

# ---------------------------------------------------------------------------
bold "6. Stop the proxy so the chain is checkpointed to its last record"
docker stop -t 5 "$PROXY" >/dev/null 2>&1 || true
sleep 0.5
# The containers run as root, and the proxy writes evidence 0600 -- correctly.
# On a Linux host that leaves the chain owned by root and unreadable to the
# user scoring it (Docker Desktop hides this by remapping ownership). Hand the
# artefacts back to whoever ran this script; the modes stay as written.
docker run --rm -v "$WORK/evidence:/e" agwgym-base \
    chown -R "$(id -u):$(id -g)" /e
info "$(wc -l < "$WORK/evidence/chain.jsonl" | tr -d ' ') lines of evidence"

# ---------------------------------------------------------------------------
bold "7. Score"
#
# Three artefacts from three containers: what the agent says it did, what the
# world says it received, and what the proxy says it authorized.
set +e
"$WORK/bin/agw-gym-host" score \
    --seed "$SEED" --workload "$WORKLOAD" \
    --results "$WORK/evidence/results.json" \
    --control "http://127.0.0.1:${CONTROL_PORT}" \
    --evidence "$WORK/evidence/chain.jsonl" \
    --public-key "$WORK/conf/checkpoint.pub" \
    --json "$WORK/report.json"
STATUS=$?
set -e

echo
info "artefacts in $WORK"
info "reproduce this exact world with: ./gym/contained.sh --seed $SEED"
exit $STATUS
