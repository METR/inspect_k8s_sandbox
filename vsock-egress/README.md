# vsock-egress

An HTTP proxy port, and a way to its sibling services, for a pod in an AWS Nitro Sandbox that has no network device.

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

In a release whose `egressForwarderImage` is set, a pod with no network device also reaches the services it shares a
network with, over TCP, and they reach it. An init container runs `vsock-egress redirect` once, as root with
`NET_ADMIN`: it makes `198.18.0.0/15` the VM's own, where each sibling has an address in `198.18.0.0/16`, and a
datagram or a ping to one fails where it is sent (`EPERM`). A sibling's connection arrives at `198.19.0.1` from
`198.18.0.0`, whichever sibling made it, so a server that listens on `127.0.0.1` alone does not take it. A connection to a
port with no server is accepted and then reset: a readiness check has to exchange data. A program that uses the pod's
HTTP proxy needs its siblings' names in `no_proxy`. A pod's connections to its siblings count among its forwarder's
64, and those its siblings make to it, 64 at most, among its worker's 128. A pod's worker reaches a sibling's at port
3134 of its pod: the release's ingress policies decide which pods reach that port. Admit `NET_ADMIN` for that init
container alone, as the chart renders it and from the image you built, on a pod with no network device, and refuse
exec into it.

A pod with no network device that carries the annotation `inspect-k8s-sandbox/ingress-listen` is reached from outside
its release too: its worker takes a connection on each port the annotation lists (1024 to 65535 other than 3134, with
commas between) and hands it to the same port in the sandbox, at `198.19.0.1`, so such a pod runs the forwarder and
the redirect whatever its siblings. The chart adds no network policy for those ports: yours says who reaches them. A
connection made before the sandbox's server listens is accepted and then reset.

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

A pod's forwarder passes its startup probe once its worker listens, so where no launcher runs the pod does not start.
A new pod's forwarder can be a newer build than the worker it meets: builds must interoperate on the wire, or the
launchers be replaced before the forwarders.

A forwarder writes `vsock connect 2:3129: <why>` each time its connection to the node fails, and `forward_failed:
<why>` when it ends with an error. Each line the launcher's container writes about a failure, its workers' among
them, has one word to alarm on:

- `<pod>: no_worker: <why>`: for a minute the sandbox has had no worker, or none that ran a minute, so no egress or
  egress that keeps breaking. Again each minute while that lasts.
- `uid <n>: worker_not_ended: <why>`: the launcher has failed for a minute to end a worker's processes, and no
  sandbox of that uid gets a worker meanwhile. Again each minute while that lasts.
- `launch_failed: <why>` and `<pod>: work_failed: <why>`: the launcher or a worker ended with an error.
- `<pod>: proxy_unreached: <why>`, then `<pod>: proxy_unreached: <n> streams since the last report` each minute.
- `<pod>: streams_refused: a stream with no key, to no proxy or sibling of the pod's or no port it serves, or past the 128 open, of which those made to the pod may hold 64`
  and `<pod>: key_unfetched: <why>`, then their counts each minute: what a sandbox or its siblings can cause. Until a
  fetch of the key succeeds its streams are refused.
- `<pod>: sibling_unreached: <why>` and `<pod>: guest_unreached: <why>`, then their counts each minute: the worker
  could not reach a sibling's worker, or its own VM's forwarder for a sibling's connection. A sandbox or its siblings
  can cause both: a sibling that is not up yet is one.

`gate.sh` proves the path to the proxy with real traffic on a node set aside for it. It runs `vsock-egress check` there,
which names the assumption about AWS's runtime that broke. The `canary` that `check` meets in the sandbox ends by
itself after 90 seconds: start `check` within them.
