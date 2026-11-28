# vsock-egress

An HTTP proxy port, a way to its sibling services, and a port others reach it on, for a pod in an AWS Nitro Sandbox
that has no network device.

A pod annotated `inspect-k8s-sandbox/egress-proxy: "<service>.<namespace>.svc.cluster.local:<port>"`, in a release whose
`egressForwarderImage` value is an image built from this directory, gets a proxy at `127.0.0.1:3128` that reaches only
that Service of its own namespace. Its forwarder has requests and limits of 500m of CPU and 256Mi of memory.

The pod's network policy admits that port on the release's own pods alone, so the Service's pods must carry the
release's `app.kubernetes.io/name` and `app.kubernetes.io/instance` labels and listen on that port. Pods that
`additionalResources` adds with those labels come under the release's other policies too: they need a policy that admits
the pod on that port, and reach only what the release's egress grants and their own policies allow. For any other
Service, add a policy that lets the pod reach it. The worker resets a connection once the proxy has left a write of its
upload uncompleted, or its end unacknowledged, for five minutes, and the forwarder does the same for the sandbox's
client and its reply.

In a release whose `egressForwarderImage` is set, the pods with no network device also reach each other over TCP, where
they share a network and have a DNS record. An init container runs `vsock-egress redirect` once, as root with
`NET_ADMIN`: it makes `198.18.0.0/15` the VM's own, where each sibling has an address in `198.18.0.0/16`, and a datagram
or a ping to one fails where it is sent (`EPERM`). A sibling's connection arrives at `198.19.0.1`, the VM's own address,
from `198.19.0.2`, whichever sibling made it: a server takes it if it listens on every address or on that one, and not
on `127.0.0.1` alone, where the service's own names lead. Every such VM has those two addresses, so one a program reads
from its own machine leads a sibling that is handed it back to itself: hand siblings names. No server there can listen
on every address at port 3128, which the forwarder holds on `127.0.0.1`. A connection to a port with no server, or to an
address of `198.18.0.0/16` that is no sibling's, is accepted and then reset: a readiness check has to exchange data. The
five-minute bounds above hold for a sibling's connection too. A program that uses the pod's HTTP proxy needs its
siblings' names in `no_proxy`. A pod's connections to its siblings count among its forwarder's 64, and those made to it,
64 at most, among its worker's 128: each holds its place until both of its ends have closed it. Its siblings together
get about 28,000 short connections a minute to each of its ports, since each is delivered from the one address. A pod's
worker reaches a sibling's at port 3134 of its pod: the release's ingress policies decide which pods reach that port,
and a policy of yours that names another port of the pod sees none of what its siblings send it. Admit `NET_ADMIN` for
that init container alone, as the chart renders it and from the image you built, on a pod with no network device, and
refuse exec into it.

A pod with no network device that carries the annotation `inspect-k8s-sandbox/ingress-listen` is reached from outside
its release too: its worker takes a connection on the port the annotation names (1024 to 65535 other than 3128 and 3134)
and hands it to the same port in the sandbox, at `198.19.0.1` as a sibling's, under the same five-minute bounds: its
server must listen on every address or on that one. Such a pod runs the forwarder, which holds `127.0.0.1:3128` there
too, and the redirect, with or without siblings. The chart adds no network policy for that port: the release's ingress
policies apply to it as to the pod's other ports, and yours says who else reaches it. A connection made before the
sandbox's server listens is accepted and then reset, so a kubelet `tcpSocket` probe on that port passes whatever the
server does, and one that is open ends with the pod's worker: a restart of the launcher's container, as on a rollout,
resets it.

Each node needs these three. `vsock-egress install <the kubelet's seccomp directory>` writes the first two:

- `profiles/<architecture>/vsock-egress.json`, in the kubelet's seccomp directory as `profiles/vsock-egress.json`:
  containerd 2.3.7's default profile for a container with no capability, plus `socket(AF_VSOCK)` and less the one
  `ioctl` that `/dev/nsm`, the Nitro Secure Module, takes, for the pod's forwarder. Any pod that names it can open the
  vsock, so admit it for that container alone. `install` writes it first as `profiles/.vsock-egress.json`: admit
  that name for no container.
- `profiles/<architecture>/vsock-egress-launcher.json`, beside it: that default, less the six calls that set a
  process's scheduling or priority, plus `setns` into a network namespace, for the launcher.
- `vsock-egress launch` as process 1 of a container of its own, as root with the capabilities `SYS_ADMIN`, `SETUID` and
  `SETGID` and no other, under the launcher's profile, with the node's `/var/lib/nitro-sandbox/firecracker` and
  `/run/netns` mounted with `HostToContainer` propagation and `/var/lib/cni/results` read-only. Keep its pod off the
  host network, or a sandbox deleted before the launcher started can raise `no_worker`. Every sandbox's worker runs in
  that container's cgroup. Measured there: an idle worker holds 4 MiB, a sandbox that stops reading 64
  downloads 86 MiB, and one whose guest does its worst 308 MiB. Give the container a CPU request, a memory limit for
  as many sandboxes as the node can hold, and a memory request that its idle workers and one sandbox's worst fit in.
  Past the limit the kernel kills every process in the container unless the kubelet's `singleProcessOOMKill` is on.
  With it on the kernel ends one process; were that the launcher, every worker would end with it. Each worker sets
  its `oom_score_adj` to 1000 so that it is a worker instead: the one with the most resident memory, whichever
  sandbox filled the socket buffers, so one sandbox can cost another its worker. That holds only while a thousandth
  of the limit for each point of the launcher's own `oom_score_adj` below 1000 comes to more than the launcher's
  resident memory over that worker's; the kubelet sets the launcher's `oom_score_adj` from the memory request and
  the node's memory.

A command run in the forwarder's container runs under the profile that admits the vsock, and need not be
`/vsock-egress`: on runc, `/proc/self/exe` there is runc itself. `forward`, `ready` and `canary` take no vsock port or
address from their caller. To bound what runs there, refuse exec into this container, admitting at most
`/vsock-egress canary`, which `gate.sh` runs.

A pod's forwarder passes its startup probe once its worker listens, so where no launcher runs the pod does not start. A
new pod's forwarder can be a newer build than the worker it meets, and a pod can carry an annotation that an older
launcher does not read, which then starts it a worker that serves less, or none: builds must interoperate on the wire,
or the launchers be replaced before the forwarders and before any pod carries such an annotation.

A forwarder writes `vsock connect 2:3129: <why>` each time its connection to the node fails (`2:3132` on the way to
a sibling), and `forward_failed: <why>` when it ends with an error. Each line the launcher's container writes about a
failure, its workers' among them, has one word to alarm on:

- `<pod>: no_worker: <why>`: for a minute the sandbox has had no worker, or none that ran a minute, so no egress or
  egress that keeps breaking. Again each minute while that lasts.
- `uid <n>: worker_not_ended: <why>`: the launcher has failed for a minute to end a worker's processes, and no
  sandbox of that uid gets a worker meanwhile. Again each minute while that lasts.
- `launch_failed: <why>` and `<pod>: work_failed: <why>`: the launcher or a worker ended with an error.
- `<pod>: proxy_unreached: <why>`, then `<pod>: proxy_unreached: <n> streams since the last report` each minute.
- `<pod>: streams_refused: a stream with no key, to no proxy or sibling of the pod's or no port it serves, or past the 128 open, of which those made to the pod may hold 64`
  and `<pod>: key_unfetched: <why>`, then their counts each minute: what a sandbox, or what connects to it, can cause.
  Until a fetch of the key succeeds its streams are refused.
- `<pod>: sibling_unreached: <why>` and `<pod>: guest_unreached: <why>`, then their counts each minute: the worker
  could not reach a sibling's worker, or its own VM's forwarder for a connection made to the pod. A sandbox, or what
  connects to it, can cause both: a sibling that is not up yet is one.

`gate.sh` proves the path to the proxy with real traffic on a node set aside for it. It runs `vsock-egress check` there,
which names the assumption about AWS's runtime that broke. The `canary` that `check` meets in the sandbox ends by
itself after 90 seconds: start `check` within them.
