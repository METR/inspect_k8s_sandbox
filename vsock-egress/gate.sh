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
  LAUNCHERS    namespace/name of the DaemonSet that runs `vsock-egress launch` on the nodes under test; it must not
               tolerate the taint inspect-k8s-sandbox/gate
  NODE         the node the sandbox is put on, one set aside for the gate: its launcher is deleted in step 7, which
               resets the connections of every other sandbox there, and the node carries the taint
               inspect-k8s-sandbox/gate:NoSchedule while the sandbox is deleted
  LISTED, UNLISTED  a URL the proxy allows and one it refuses (defaults: pypi.org's and example.com's)
  LABELS       labels for the release and the gate's own pod, as a JSON object (default {})
  KEEP=1       leave the release installed when a step fails
It needs helm, kubectl, python3 and RBAC to patch nodes, and leaves nothing behind: one helm release, and one pod
with the node's process list and a read-only mount of its VM directories. A run killed in step 7 leaves the taint,
and no launcher comes to NODE until `kubectl taint node NODE inspect-k8s-sandbox/gate-`. Exit 0: every step passed.
Exit 1: a step failed, and step 6 (`vsock-egress check`) says which assumption about AWS's runtime broke, if one did.
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
REL=gate-$(date -u +%H%M%S)-$RANDOM$RANDOM # no other run's name: cleanup removes the release of this name, whole or half installed
TAINT=inspect-k8s-sandbox/gate
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
  [ -n "${tainted:-}" ] && k taint node "$node" "$TAINT-" > /dev/null 2>&1
  [ "$failed" = 1 ] && [ "${KEEP:-}" = 1 ] && { echo "   kept: helm release $REL and pod $REL-peek in $NS"; return; }
  h uninstall "$REL" --ignore-not-found --wait --timeout 120s > /dev/null 2>&1
  k -n "$NS" delete pod "$REL-peek" --ignore-not-found --wait=false > /dev/null 2>&1
}
# A taint there is another run's in step 7, or one a killed run left: neither is this run's to take off.
held=$(k get node "$NODE" -o jsonpath="{.spec.taints[?(@.key==\"$TAINT\")].key}") && [ -z "$held" ] \
  || { echo "$NODE was not read, or carries the taint $TAINT: a run is in step 7 there, or was killed in it. After a killed run: kubectl --context $CONTEXT taint node $NODE $TAINT-" >&2; exit 2; }
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
[ -n "$selector" ] || { fail "no labels select the launchers: DaemonSet $LAUNCHERS was not read, or has no matchLabels"; exit 1; }
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
workers() { peek 'for p in /proc/[0-9]*; do { tr "\0" " " < $p/cmdline; } 2>/dev/null | grep -q "^/vsock-egress work .*'"$NS/$SANDBOX"'" && echo ${p#/proc/}; done; '"${1:-true}" | tr '\n' ' '; }
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

# The AF_VSOCK refusal must survive the masked-family trick; the carry closes the io_uring and 32-bit routes, noted where off.
vprobe=$(in_sandbox python3 -c '
import base64, ctypes, errno, os, platform, socket, subprocess, tempfile
libc = ctypes.CDLL(None, use_errno=True)
sys_socket = 41 if platform.machine() == "x86_64" else 198  # the syscall carries the full 64-bit family, which libc may truncate
ctypes.set_errno(0)
fd = libc.syscall(sys_socket, ctypes.c_long((1 << 32) | socket.AF_VSOCK), socket.SOCK_STREAM, 0)
if fd >= 0:
    os.close(fd)
    print("HIGHBITS=OPENED")
else:
    print("HIGHBITS=" + ("REFUSED" if ctypes.get_errno() in (errno.EPERM, errno.EAFNOSUPPORT) else "ERR"))
cmd = open("/proc/cmdline").read().split()
print("CARRY_IOURING=" + ("on" if "sysctl.kernel.io_uring_disabled=2" in cmd else "off"))
print("CARRY_IA32=" + ("on" if "ia32_emulation=0" in cmd else "off"))
ctypes.set_errno(0)
ring = libc.syscall(425, 1, ctypes.create_string_buffer(120))
if ring >= 0:
    os.close(ring)
print("IOURING=" + ("ENABLED" if ring >= 0 else "DISABLED" if ctypes.get_errno() == errno.EPERM else "ERR"))
if platform.machine() != "x86_64":
    print("I386=NA")
else:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(base64.b64decode("f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAhgAAAAYAAAAAUAAAAAEAAAuAEAAAC7KgAAAM2A"))
    os.chmod(f.name, 0o755)
    try:
        subprocess.run([f.name])
        print("I386=RAN")
    except OSError as e:
        print("I386=" + ("REFUSED" if e.errno == errno.ENOEXEC else "ERR"))
    os.unlink(f.name)
print("PROBE_DONE")
' 2>&1 | tr "\n" " ")
case "$vprobe" in *PROBE_DONE*) ;; *) fail "the bypass probe did not run to completion: $vprobe" ;; esac

say "5a. the masked-family socket(AF_VSOCK) is refused too"
case "$vprobe" in
  *HIGHBITS=REFUSED*) pass "socket() with the family's upper bits set is refused: $vprobe" ;;
  *) fail "a masked-family socket(AF_VSOCK) opened — seccomp compares the family as 64 bits: $vprobe" ;;
esac

say "5b. io_uring cannot open AF_VSOCK (the IORING_OP_SOCKET bypass)"
case "$vprobe" in
  *CARRY_IOURING=off*) echo "   note: io_uring is not disabled on this node's guests (carry off); observed $vprobe" ;;
  *IOURING=DISABLED*) pass "io_uring_setup is refused: $vprobe" ;;
  *) fail "the guest carries io_uring_disabled=2 but io_uring_setup was not refused with EPERM: $vprobe" ;;
esac

say "5c. a 32-bit socketcall cannot open AF_VSOCK"
case "$vprobe" in
  *CARRY_IA32=off*) echo "   note: 32-bit programs are not refused on this node's guests (carry off); observed $vprobe" ;;
  *I386=REFUSED*|*I386=NA*) pass "a 32-bit program is refused: $vprobe" ;;
  *) fail "the guest carries ia32_emulation=0 but a 32-bit program ran: $vprobe" ;;
esac

say "5d. the forwarder's profile refuses the ioctl of the Nitro Secure Module"
nsm=$(k -n "$NS" exec "$SANDBOX" -c gate-probe -- python3 -c '
import ctypes, errno, os, platform
libc = ctypes.CDLL(None, use_errno=True)
fd = os.open("/dev/null", os.O_RDONLY)
said = []
for command in 0xC0200A00, 1 << 32 | 0xC0200A00, 0xC0200A01:  # the module command, the same past the 32 bits the kernel reads, and another
    ctypes.set_errno(0)
    libc.syscall(16 if platform.machine() == "x86_64" else 29, fd, ctypes.c_ulong(command), 0)
    said.append(errno.errorcode.get(ctypes.get_errno(), "TAKEN"))
print(*said)
' 2>&1 | tail -1)
[ "$nsm" = "EPERM EPERM ENOTTY" ] && pass "under the node's profiles/vsock-egress.json the module's ioctl is refused and another reaches the driver: $nsm" \
  || fail "under the forwarder's profile ioctl 0xC0200A00, the same with bit 32 set, and 0xC0200A01 on /dev/null gave '$nsm', not 'EPERM EPERM ENOTTY'"

say "6. the contract with the runtime (vsock-egress check on the node, canary in the guest)"
k -n "$NS" exec "$SANDBOX" -c egress-forwarder -- /vsock-egress canary > /dev/null 2>&1 & canary=$!
pod=$(launcher)
contract=$(k -n "$LNS" exec "$pod" -c "$(k -n "$LNS" get pod "$pod" -o jsonpath='{.spec.containers[0].name}')" -- /vsock-egress check -pod "$NS/$SANDBOX" -wait 60s 2>&1 | tail -3 | tr '\n' ' ')
kill "$canary" 2> /dev/null; canary=
case "$contract" in *"ok: "*) pass "$contract" ;; *) fail "check: $contract" ;; esac
vm=$(echo "$contract" | sed -n 's|.* at /var/lib/nitro-sandbox/firecracker/\([0-9a-f]*\)/root.*|\1|p')

say "6a. the sandbox's pod is deleted while its node's launcher runs: its worker and VM directory go, and the pod that follows gets a worker from that launcher"
at() { peek "tr '\\0' ' ' < /proc/${1:-none}/cmdline" 2> /dev/null | sed -n 's|.* -vsock [^ ]*/\([0-9a-f]\{12\}\)/root/vm.vsock .*|\1|p'; } # a worker's VM directory
by() { peek "awk '/^PPid/{print \$2}' /proc/${1:-none}/status" 2> /dev/null; } # and the process that started it: its launcher
was=$(echo $(workers)); before=$(at "$was"); from=$(by "$was"); uid=$(k -n "$NS" get pod "$SANDBOX" -o jsonpath='{.metadata.uid}')
# The StatefulSet makes the pod again under its name: Ready there says its forwarder has met a new worker.
reborn() { local now; now=$(k -n "$NS" get pod "$SANDBOX" -o jsonpath='{.metadata.uid} {.status.conditions[?(@.type=="Ready")].status}') && [ "${now% *}" != "$uid" ] && [ "${now#* }" = True ]; }
dir_gone() { [ "$(peek "[ -e /vms/. ] && { [ -e /vms/$1 ] || echo gone; }")" = gone ]; } # not where the VM directories cannot be read at all
moved() { # one new worker and no other: the node says `looked` after naming them all, as an answer cut short could hide the old one
  seen=$(echo $(workers 'echo looked')); now=${seen%looked}; now=${now% }; new=$(at "$now")
  [ "$seen" != "$now" ] && [ -n "$new" ] && [ "$new" != "$before" ]
}
if [ -n "$uid" ] && [ -n "$before" ] && [ -n "$from" ] && k -n "$NS" delete pod "$SANDBOX" --wait=false > /dev/null && wait_for 300 reborn; then
  wait_for 120 dir_gone "$before" # the node can stop the old VM after the new pod is up: its directory goes then, and its worker at the launcher's next pass
  # A launcher that ended instead would have taken every worker on the node with it, and its successor would start this one too.
  wait_for 60 moved && vm=$new && dir_gone "$before" && [ "$(by "$now")" = "$from" ] \
    && pass "worker $was and VM directory $before went with the pod; the pod that followed has worker $now and VM directory $vm, from the same launcher (pid $from)" \
    || fail "after the pod was deleted under a running launcher: the node named workers '$seen' (it was '$was') at VM directory '$new' (it was '$before', which is $(peek "[ -e /vms/$before ] && echo still there || echo gone")), started by pid '$(by "$now")' (it was '$from')"
else
  fail "the pod $SANDBOX or its worker was not read (VM directory '$before', started by pid '$from'), the pod was not deleted, or no new one became Ready"
fi

say "7. the sandbox is deleted while its node's launcher is stopped: nothing of it is left on the node"
peek "ls -d /vms/${vm:-none}" > /dev/null 2>&1 || fail "the pod's VM directory was not found before the delete: '${vm:-}'"
old=$(launcher)
owner=$(k -n "$LNS" get daemonset "$LDS" -o jsonpath='{.metadata.uid}')
[ -n "$owner" ] && [ "$(k -n "$LNS" get pod "$old" -o jsonpath='{.metadata.ownerReferences[0].uid}')" = "$owner" ] \
  || { fail "the pod '$old' is not one of DaemonSet $LAUNCHERS: it is left alone"; exit 1; }
# The taint keeps the DaemonSet from putting a launcher back on the node before the sandbox has gone.
k taint node "$node" "$TAINT:NoSchedule" > /dev/null && tainted=1 || { fail "the node was not tainted $TAINT"; exit 1; }
k -n "$LNS" delete pod "$old" --wait=false > /dev/null
wait_for 60 sh -c "kubectl --context '$CONTEXT' --request-timeout=60s -n '$LNS' get pod '$old' 2>&1 | grep -q '(NotFound)'" || fail "the launcher $old is still there"
h uninstall "$REL" --wait --timeout 180s > /dev/null 2>&1 || fail "helm uninstall"
# A pod can leave the API before its node has stopped it: that the VM's directory has gone is the node's own word.
if wait_for 120 sh -c "kubectl --context '$CONTEXT' --request-timeout=60s -n '$NS' get pod '$SANDBOX' 2>&1 | grep -q '(NotFound)'" && wait_for 120 dir_gone "$vm"; then
  back=$(k -n "$LNS" get pods -l "$selector" --field-selector "spec.nodeName=$node" -o name) && [ -z "$back" ] \
    || fail "a launcher was on the node while the sandbox went, or the launchers were not listed: '$back' (does the DaemonSet tolerate the taint $TAINT?)"
else
  fail "the sandbox pod, or its VM directory $vm, is still there"
fi
k taint node "$node" "$TAINT-" > /dev/null && tainted= || fail "the taint $TAINT was not taken off $node"
wait_for 120 sh -c "[ -n \"\$(kubectl --context '$CONTEXT' --request-timeout=60s -n '$LNS' get pods -l '$selector' --field-selector 'spec.nodeName=$node,status.phase=Running' -o name | grep -v '$old')\" ]" \
  && pass "a new launcher runs on the node: $(launcher) (the old one was $old)" || fail "no new launcher on $node"
# The node names each worker and the VM directory it finds, then says `looked`: an exec that fails, or is cut short, does not.
left() { echo $(workers "[ -e /vms/$vm ] && echo /vms/$vm; [ -e /vms/. ] && echo looked"); }
gone() { found=$(left); [ "$found" = looked ]; }
wait_for 60 gone || true
[ "$found" = looked ] && pass "no worker of the pod and no VM directory $vm is left on the node (VM directories there: $(peek 'ls /vms | wc -l'))" || fail "left on the node, or the node did not answer: '$found'"

echo
[ "$failed" = 0 ] && { echo "GATE PASSED $(date -u +%FT%TZ) on $node"; exit 0; }
echo "GATE FAILED $(date -u +%FT%TZ) on $node"
exit 1
