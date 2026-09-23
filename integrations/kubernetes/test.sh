#!/usr/bin/env bash
# Prove sidecar confinement and the admission policy on a real cluster.
#
#   ./test.sh                 # creates a kind cluster, runs, deletes it
#   KEEP=1 ./test.sh          # leave the cluster up afterwards
#
# Needs docker and kind. Uses the manifests in this directory as shipped,
# with the image names swapped for locally built ones.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=../..
CLUSTER=agw-k8s-test
CTX=kind-$CLUSTER
k() { kubectl --context "$CTX" "$@"; }
fail() { echo "FAIL: $*"; k -n agw-demo get pods -o wide 2>/dev/null || true; exit 1; }

cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "KEEP=1: cluster $CLUSTER left up"; return; }
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v kind >/dev/null || { echo "needs kind: go install sigs.k8s.io/kind@latest"; exit 1; }
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --wait 120s >/dev/null

docker build -q -f "$ROOT/Dockerfile.agw" -t agw:k8s-test "$ROOT" >/dev/null
docker build -q -f "$ROOT/integrations/docker-sidecar/Dockerfile.attacker" -t agw-attacker:k8s-test \
  "$ROOT/integrations/docker-sidecar" >/dev/null
kind load docker-image agw:k8s-test agw-attacker:k8s-test --name "$CLUSTER" >/dev/null
# A kept cluster may still have pods from a previous run on the old image.
kubectl --context "$CTX" delete namespace agw-demo --ignore-not-found --wait=true >/dev/null 2>&1 || true

echo "== admission policy"
k apply -f admission-policy.yaml >/dev/null
sleep 3 # the policy is enforced once the API server has compiled it

manifest() { sed -e 's#ghcr.io/aryan22g/agw:v[0-9.]*#agw:k8s-test#' confined-agent.yaml; }
# pod_only prints just the Pod document of a multi-document manifest.
pod_only() { python3 -c 'import sys; print(next(d for d in sys.stdin.read().split("\n---\n") if "kind: Pod" in d))'; }

echo "== the shipped example is admitted and works"
manifest | k apply -f - >/dev/null
k -n agw-demo wait --for=condition=Ready pod/confined-agent --timeout=120s >/dev/null || fail "example pod not ready"
for _ in $(seq 1 30); do k -n agw-demo logs confined-agent -c agent 2>/dev/null | grep -q "pypi.org" && break; sleep 1; done
k -n agw-demo logs confined-agent -c agent | grep -q "pypi.org 200" || fail "agent could not reach pypi.org through the proxy"
echo "agent: $(k -n agw-demo logs confined-agent -c agent)"

echo "== an attacker with root in the agent container"
# The same pod, with the attacker as the agent, running as root with every
# capability dropped -- which the admission policy permits, because root
# without capabilities cannot undo the rule.
manifest | sed -e 's/name: confined-agent$/name: attacker/' \
  -e 's#image: curlimages/curl:latest#image: agw-attacker:k8s-test#' \
  -e 's#command: \["sh", "-c", "curl.*"\]#command: ["sleep", "3600"]#' \
  -e 's/runAsUser: 10000/runAsUser: 0/' -e 's/runAsNonRoot: true/runAsNonRoot: false/' \
  | pod_only | k apply -f - >/dev/null
k -n agw-demo wait --for=condition=Ready pod/attacker --timeout=120s >/dev/null || fail "attacker pod not ready"
out=$(k -n agw-demo exec attacker -c agent -- sh /attack.sh)
echo "$out"
check() { echo "$out" | grep -E "^$1 +$2\$" >/dev/null || fail "$1: expected $2"; }
check "whoami"                  "0"
check "via proxy: pypi.org"     "200"
check "via proxy: example.com"  "(403|blocked)"
check "via proxy: metadata"     "403"
check "direct: pypi.org"        "blocked"
check "direct: metadata"        "blocked"
check "direct: dns to 1.1.1.1"  "blocked"
check "remove the firewall"     "refused"
check "become the proxy uid"    "refused"

echo "== the live proxy's evidence is anchored and verifies"
# The proxy checkpoints every 10 seconds while there is something to sign, so
# a running deployment's evidence verifies without stopping it.
ok=0
for _ in $(seq 1 20); do
  if k -n agw-demo exec attacker -c agw -- agw audit verify /evidence/evidence.jsonl \
       --key /evidence/.agw/checkpoint.key.pub --quiet >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ $ok = 1 ] || fail "the live evidence was not anchored within 20s"
k -n agw-demo exec attacker -c agw -- agw audit verify /evidence/evidence.jsonl \
  --key /evidence/.agw/checkpoint.key.pub --quiet

echo "== misconfigurations are refused at admission"
reject() {
  local what=$1; shift
  if manifest | pod_only | sed -e "s/name: confined-agent\$/name: bad-$RANDOM/" "$@" \
       | k apply -f - >/dev/null 2>err.txt; then
    fail "admitted a pod with $what"
  fi
  grep -q "agw-confined-pods" err.txt || fail "$what: refused, but not by the policy: $(cat err.txt)"
  echo "refused: $what"
}
reject "an agent keeping its capabilities"    -e '/name: agent/,$ s/drop: \["ALL"\]/drop: ["NET_RAW"]/'
reject "an agent running as the proxy's UID"  -e 's/runAsUser: 10000/runAsUser: 1337/'
reject "an agent with no runAsUser"           -e '/runAsUser: 10000/d'
reject "hostNetwork"                          -e 's/^spec:$/spec:\n  hostNetwork: true/'
# The sidecar renamed and the workload given its name, to borrow its exemption.
reject "a workload named agw"                 -e 's/    - name: agw$/    - name: proxy/' -e 's/    - name: agent$/    - name: agw/'
reject "privilege escalation"                 -e '/name: agent/,$ s/allowPrivilegeEscalation: false/allowPrivilegeEscalation: true/'

echo "== an ephemeral debug container with NET_ADMIN is refused"
if k -n agw-demo debug attacker --image=agw:k8s-test --profile=netadmin --target=agent -- true >/dev/null 2>err.txt; then
  fail "admitted an ephemeral container with NET_ADMIN into a confined pod"
fi
grep -q "agw-confined-pods" err.txt || fail "debug container refused, but not by the policy: $(cat err.txt)"
echo "refused: kubectl debug --profile=netadmin"
rm -f err.txt

echo
echo "Kubernetes sidecar confinement holds, and the admission policy enforces its preconditions."
