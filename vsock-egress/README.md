# vsock-egress

An HTTP proxy port for a pod in an AWS Nitro Sandbox that has no network device.

A pod annotated `inspect-k8s-sandbox/egress-proxy: "<service>.<namespace>.svc.cluster.local:<port>"`, in a release whose
`egressForwarderImage` value is an image built from this directory, gets a proxy at `127.0.0.1:3128` that reaches only
that Service of its own namespace. Its forwarder has no resource requests, so the pod is not of the Guaranteed QoS class.
A connection on which no byte has moved for 300 s is ended.

A pod that also carries `inspect-k8s-sandbox/egress-capture: "true"` reaches the proxy from programs that ignore proxy
settings: its forwarder is the pod's resolver. A connection to an address is carried only into a range, and on the TCP
port, that the release's `egressCaptureRanges` value names, as `10.20.0.0/24:5432`. The range's other ports are refused
at once. IPv6 and UDP other than DNS are not carried. The pod gets an init container that runs `vsock-egress redirect`
as root with `NET_ADMIN` and no other capability, which a namespace at the `baseline` Pod Security Standard refuses.

Each node needs:

- `profiles/<architecture>/vsock-egress.json`, in the kubelet's seccomp directory as `profiles/vsock-egress.json`:
  containerd 2.3.7's default profile for a container with no capability, plus `socket(AF_VSOCK)`, for the pod's
  forwarder.
- `profiles/<architecture>/vsock-egress-launcher.json`, beside it: that default, less the six calls that set a
  process's scheduling or priority, plus `setns` into a network namespace, for the launcher.
- `vsock-egress launch` as process 1 of a container of its own, as root with the capabilities `SYS_ADMIN`, `SETUID` and
  `SETGID` and no other, under the launcher's profile, with the node's `/var/lib/nitro-sandbox/firecracker` and
  `/run/netns` mounted with `HostToContainer` propagation and `/var/lib/cni/results` read-only. Every sandbox's worker
  runs in that container's cgroup. Measured there: an idle worker holds 4 MiB, a sandbox that stops reading 64
  downloads 86 MiB, and one whose guest does its worst 308 MiB. Give the container a CPU request, a memory limit for
  as many sandboxes as the node can hold, and a memory request that its idle workers and one sandbox's worst fit in.

A forwarder writes `vsock connect 2:3129: <why>` each time its connection to the node fails, and `forward_failed:
<why>` when it ends with an error. Each line the launcher's container writes about a failure, its workers' among
them, has one word to alarm on:

- `<pod>: no_worker: <why>`: the sandbox has had no worker for a minute, so no egress. Again each minute while that
  lasts.
- `uid <n>: worker_not_ended: <why>`: the launcher has failed for a minute to end a worker's processes, and no
  sandbox of that uid gets a worker meanwhile. Again each minute while that lasts.
- `launch_failed: <why>` and `<pod>: work_failed: <why>`: the launcher or a worker ended with an error.
- `<pod>: proxy_unreached: <why>`, then `<pod>: proxy_unreached: <n> streams since the last report` each minute.
- `<pod>: streams_refused: a stream with no key, or past the 128 open` and `<pod>: key_unfetched: <why>`, then their
  counts each minute: what a sandbox can cause itself. Until a fetch of the key succeeds its streams are refused.

`gate.sh` proves the whole path with real traffic on a node set aside for it. It runs `vsock-egress check` there,
which names the assumption about AWS's runtime that broke.
