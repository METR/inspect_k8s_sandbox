#!/bin/bash
# The gate for egress over the vsock: real traffic from a sandbox with no network card to its egress proxy, under the seccomp profiles the nodes hold.
usage() {
  cat >&2 <<'EOF'
usage: CONTEXT=... NS=... CHART=... LAUNCHERS=... NODE=... gate.sh VALUES.yaml
  VALUES.yaml  chart values for one service, `default`, with no network card, that names the egress proxy of its own
               release (a pod <fullname>-egress-proxy-0 that allows LISTED's host and refuses UNLISTED's), as Hawk's
               runner makes them for a strict sandbox that names a host
  CONTEXT      kubectl context
  NS           namespace to install into; it must exist
  CHART        the agent-env chart's directory
  LAUNCHERS    namespace/name of the DaemonSet that runs `vsock-egress launch` on the nodes under test
  NODE         the node the sandbox is put on, one set aside for the gate: its launcher is deleted in step 7, which
               resets the connections of every other sandbox there
  LISTED, UNLISTED  a URL the proxy allows and one it refuses (defaults: pypi.org's and example.com's)
  LABELS       labels for the release and the gate's own pod, as a JSON object (default {})
  KEEP=1       leave the release installed when a step fails
It needs helm, kubectl and python3, and leaves nothing behind: one helm release, and one pod with the node's process
list and a read-only mount of its VM directories. Exit 0: every step passed. Exit 1: a step failed, and step 6
(`vsock-egress check`) says which assumption about AWS's runtime broke, if one did.
EOF
  exit 2
}
set -u
[ $# = 1 ] && [ -n "${CONTEXT:-}" ] && [ -n "${NS:-}" ] && [ -n "${CHART:-}" ] && [ -n "${LAUNCHERS:-}" ] && [ -n "${NODE:-}" ] || usage
VALUES=$1
LABELS=${LABELS:-"{}"}
LISTED=${LISTED:-https://pypi.org/simple/sampleproject/}
UNLISTED=${UNLISTED:-https://example.com/}
LNS=${LAUNCHERS%%/*}; LDS=${LAUNCHERS##*/}
REL=gate-$(date -u +%H%M%S)
SANDBOX=agent-env-$REL-default-0
k() { kubectl --context "$CONTEXT" --request-timeout=60s "$@"; }
h() { HELM_DRIVER=configmap helm --kube-context "$CONTEXT" --namespace "$NS" "$@"; }
failed=0
say() { echo "== $(date -u +%T) $*"; }
pass() { echo "   PASS  $*"; }
fail() { echo "   FAIL  $*"; failed=1; }
in_sandbox() { k -n "$NS" exec "$SANDBOX" -c default -- "$@"; }
peek() { k -n "$NS" exec "$REL-peek" -- sh -c "$1"; }
launcher() { k -n "$LNS" get pods -l "$selector" --field-selector "spec.nodeName=$node,status.phase=Running" -o jsonpath='{.items[0].metadata.name}'; }
wait_for() { # wait_for SECONDS COMMAND...: until the command succeeds
  local end=$(( $(date +%s) + $1 )); shift
  until "$@" > /dev/null 2>&1; do [ "$(date +%s)" -lt "$end" ] || return 1; sleep 2; done
}
cleanup() {
  [ -n "${canary:-}" ] && kill "$canary" 2> /dev/null
  [ "$failed" = 1 ] && [ "${KEEP:-}" = 1 ] && { echo "   kept: helm release $REL and pod $REL-peek in $NS"; return; }
  h uninstall "$REL" --ignore-not-found --wait --timeout 120s > /dev/null 2>&1
  k -n "$NS" delete pod "$REL-peek" --ignore-not-found --wait=false > /dev/null 2>&1
}
trap cleanup EXIT

# A second container beside the sandbox's, under the forwarder's seccomp profile: the only way to open the vsock by hand.
probe='[{"name":"gate-probe","image":"public.ecr.aws/docker/library/python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89","command":["sleep","infinity"],
 "securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"runAsNonRoot":true,"runAsUser":65532,
 "seccompProfile":{"type":"Localhost","localhostProfile":"profiles/vsock-egress.json"}}}]'

say "1. helm install $REL: a sandbox with no network card that names its release's egress proxy"
h install "$REL" "$CHART" -f "$VALUES" -f <(echo "{\"labels\":$LABELS}") --set-json "extraContainers=$probe" --set-string "services.default.nodeSelector.kubernetes\.io/hostname=$NODE" > /dev/null \
  || { fail "helm install"; exit 1; }
if wait_for 300 k -n "$NS" wait --for=condition=Ready "pod/$SANDBOX" "pod/agent-env-$REL-egress-proxy-0" --timeout=5s; then
  pass "the sandbox and its proxy are Ready (the forwarder's startup probe passed)"
else
  fail "the pods did not become Ready in 300 s"; k -n "$NS" get pods -l "app.kubernetes.io/instance=$REL" -o wide; k -n "$NS" get events --sort-by=.lastTimestamp | tail -8; exit 1
fi
node=$(k -n "$NS" get pod "$SANDBOX" -o jsonpath='{.spec.nodeName}')
[ "$node" = "$NODE" ] || { fail "the sandbox is on $node, not on $NODE"; exit 1; }
selector=$(k -n "$LNS" get daemonset "$LDS" -o jsonpath='{range .spec.selector.matchLabels}{end}{.spec.selector.matchLabels}' | python3 -c 'import json,sys; print(",".join(f"{k}={v}" for k, v in json.load(sys.stdin).items()))')
echo "   node $node; launcher $(launcher); annotations: $(k -n "$NS" get pod "$SANDBOX" -o jsonpath='{.metadata.annotations.sandbox\.amazonaws\.com/network-isolated} {.metadata.annotations.inspect-k8s-sandbox/egress-proxy}')"
[ "$(in_sandbox sh -c 'ls /sys/class/net | grep -vc -e "^lo$" -e "^dummy"; true')" = 0 ] && pass "the guest has no network device" || fail "the guest has a network device: $(in_sandbox ls /sys/class/net | tr '\n' ' ')"
k -n "$NS" get pod "$SANDBOX" -o jsonpath='{range .spec.initContainers[*]}{.name}={.securityContext.seccompProfile}{"\n"}{end}' | grep -q 'egress-forwarder=.*"localhostProfile":"profiles/vsock-egress.json"' \
  && pass "the forwarder runs under the node's profile profiles/vsock-egress.json" || fail "the forwarder is not under profiles/vsock-egress.json"
k -n "$LNS" get pod "$(launcher)" -o jsonpath='{.spec.containers[0].securityContext}' | grep -q '"localhostProfile":"profiles/vsock-egress-launcher.json"' \
  && pass "the launcher runs under profiles/vsock-egress-launcher.json" || fail "the launcher is not under profiles/vsock-egress-launcher.json"

# A pod on that node, beside the runtime: it lists the VM directories and the node's processes as uid 65533, which is no reaper's and can signal none of them.
cat <<EOF | k -n "$NS" apply -f - > /dev/null
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"$REL-peek","labels":$LABELS},
 "spec":{"nodeName":"$node","hostPID":true,"restartPolicy":"Never","terminationGracePeriodSeconds":1,"automountServiceAccountToken":false,
  "tolerations":[{"operator":"Exists"}],
  "containers":[{"name":"peek","image":"public.ecr.aws/docker/library/busybox:1.38-musl@sha256:80e38f9a1b39188b8bdb28879178edb322a4402b081a9aedda1924609decd6f6","command":["sleep","3600"],
   "securityContext":{"runAsUser":65533,"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},
   "volumeMounts":[{"name":"vms","mountPath":"/vms","readOnly":true}]}],
  "volumes":[{"name":"vms","hostPath":{"path":"/var/lib/nitro-sandbox/firecracker"}}]}}
EOF
wait_for 120 k -n "$NS" wait --for=condition=Ready "pod/$REL-peek" --timeout=5s || { fail "the peek pod did not start"; exit 1; }
workers() { peek 'for p in /proc/[0-9]*; do { tr "\0" " " < $p/cmdline; } 2>/dev/null | grep -q "^/vsock-egress work .*'"$NS/$SANDBOX"'" && echo ${p#/proc/}; done; true' | tr '\n' ' '; }
worker=$(workers); uid=$(peek "awk '/^Uid/{print \$2}' /proc/${worker%% *}/status" 2> /dev/null); caps=$(peek "awk '/^CapEff/{print \$2}' /proc/${worker%% *}/status" 2> /dev/null)
[ "$(echo $worker | wc -w)" -eq 1 ] && [ "${uid:-0}" != 0 ] && [ "$caps" = 0000000000000000 ] \
  && pass "one worker for the pod on its node: pid $worker, uid $uid, CapEff $caps" \
  || fail "expected one worker for $NS/$SANDBOX on $node, not root and with no capability: pids '$worker', uid '$uid', CapEff '$caps'; the launcher says: $(k -n "$LNS" logs "$(launcher)" --tail=5 2>&1 | tr '\n' '|')"

say "2. a listed host answers"
code=$(in_sandbox curl -sS -o /dev/null -m 60 -w '%{http_code} in %{time_total}s' "$LISTED" 2>&1)
[ "${code%% *}" = 200 ] && pass "GET $LISTED -> $code (HTTPS_PROXY=$(in_sandbox sh -c 'echo $HTTPS_PROXY'))" || fail "GET $LISTED -> $code"
out=$(in_sandbox sh -c 'rm -rf /tmp/gate-pip; pip download --no-cache-dir --disable-pip-version-check -q -d /tmp/gate-pip requests > /tmp/gate-pip.log 2>&1; echo "rc $? files $(ls /tmp/gate-pip 2>/dev/null | wc -l)"; rm -rf /tmp/gate-pip')
[ "${out%% files*}" = "rc 0" ] && pass "pip download requests -> $out" || fail "pip download requests -> $out: $(in_sandbox tail -2 /tmp/gate-pip.log | tr '\n' ' ')"

say "3. an unlisted host is refused by the proxy"
code=$(in_sandbox curl -sS -o /dev/null -m 30 -w '%{http_connect}/%{http_code}' "$UNLISTED" 2> /dev/null)
[ "$code" = "403/000" ] && pass "GET $UNLISTED -> the proxy answered CONNECT with 403" || fail "GET $UNLISTED -> CONNECT/status $code, expected 403/000"

say "4. a stream that opens with a wrong key is refused"
answer=$(k -n "$NS" exec "$SANDBOX" -c gate-probe -- python3 -c '
import socket
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.settimeout(20); s.connect((2, 3129))
s.sendall(bytes(32) + (18).to_bytes(4, "big") + b"GET / HTTP/1.0\r\n\r\n")
try:
    data = s.recv(100)
    print("closed with no byte" if data == b"" else "ANSWERED %r" % data)
except ConnectionResetError:
    print("reset with no byte")
' 2>&1 | tail -1)
case "$answer" in closed*|reset*) pass "32 zero bytes for a key, then a request: $answer" ;; *) fail "32 zero bytes for a key: $answer" ;; esac
code=$(in_sandbox curl -sS -o /dev/null -m 60 -w '%{http_code}' "$LISTED" 2>&1)
[ "$code" = 200 ] && pass "the forwarder's own streams still pass: $code" || fail "after the refusal GET $LISTED -> $code"

say "5. the service's own container is refused socket(AF_VSOCK)"
opened=$(in_sandbox python3 -c 'import socket
try:
    socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); print("opened")
except PermissionError:
    print("refused")' 2>&1 | tail -1)
[ "$opened" = refused ] && pass "the call is refused there: the default seccomp profile is applied in the guest" \
  || fail "socket(AF_VSOCK) in the service's container: $opened. The default seccomp profile is not applied in the guest"

say "6. the contract with the runtime (vsock-egress check on the node, canary in the guest)"
k -n "$NS" exec "$SANDBOX" -c egress-forwarder -- /vsock-egress canary > /dev/null 2>&1 & canary=$!
contract=$(k -n "$LNS" exec "$(launcher)" -c launcher -- /vsock-egress check -pod "$NS/$SANDBOX" -wait 60s 2>&1 | tail -3 | tr '\n' ' ')
kill "$canary" 2> /dev/null; canary=
case "$contract" in *"ok: "*) pass "$contract" ;; *) fail "check: $contract" ;; esac
vm=$(echo "$contract" | sed -n 's|.* at /var/lib/nitro-sandbox/firecracker/\([0-9a-f]*\)/root.*|\1|p')

say "7. the sandbox is deleted while its node's launcher is stopped: nothing of it is left on the node"
peek "ls -d /vms/${vm:-none}" > /dev/null 2>&1 || fail "the pod's VM directory was not found before the delete: '${vm:-}'"
old=$(launcher)
k -n "$LNS" delete pod "$old" --wait=false > /dev/null
h uninstall "$REL" --wait --timeout 180s > /dev/null 2>&1 || fail "helm uninstall"
wait_for 120 sh -c "! kubectl --context '$CONTEXT' -n '$NS' get pod '$SANDBOX' > /dev/null 2>&1" || fail "the sandbox pod is still there"
wait_for 120 sh -c "[ -n \"\$(kubectl --context '$CONTEXT' -n '$LNS' get pods -l '$selector' --field-selector 'spec.nodeName=$node,status.phase=Running' -o name | grep -v '$old')\" ]" \
  && pass "a new launcher runs on the node: $(launcher) (the old one was $old)" || fail "no new launcher on $node"
gone() { [ -z "$(workers)" ] && ! peek "ls -d /vms/$vm" > /dev/null 2>&1; }
wait_for 60 gone || true
[ -z "$(workers)" ] && pass "no worker of the pod is left on the node" || fail "a worker of the pod is left: pid $(workers)"
peek "ls -d /vms/$vm" > /dev/null 2>&1 && fail "its VM directory is still there: $vm" || pass "its VM directory is gone: $vm (VM directories left on the node: $(peek 'ls /vms | wc -l'))"

echo
[ "$failed" = 0 ] && { echo "GATE PASSED $(date -u +%FT%TZ) on $node"; exit 0; }
echo "GATE FAILED $(date -u +%FT%TZ) on $node"
exit 1
