# vsock-egress

An HTTP proxy port for a pod in an AWS Nitro Sandbox that has no network device.

A pod annotated `inspect-k8s-sandbox/egress-proxy: "<service>.<namespace>.svc.cluster.local:<port>"`, in a release whose
`egressForwarderImage` value is an image built from this directory, gets a proxy at `127.0.0.1:3128` that reaches only
that Service of its own namespace. Its forwarder has no resource requests, so the pod is not of the Guaranteed QoS class.

Each node needs:

- `profiles/<architecture>/vsock-egress.json`, in the kubelet's seccomp directory as `profiles/vsock-egress.json`:
  containerd 2.3's default profile for a container with no capability, plus `socket(AF_VSOCK)`, for the pod's forwarder.
- `profiles/<architecture>/vsock-egress-launcher.json`, beside it: the same default plus `setns` into a network
  namespace, for the launcher.
- `vsock-egress launch` as process 1 of a container of its own, as root with the capabilities `SYS_ADMIN`, `SETUID` and
  `SETGID` and no other, under the launcher's profile, with the node's `/var/lib/nitro-sandbox/firecracker` and
  `/run/netns` mounted with `HostToContainer` propagation and `/var/lib/cni/results` read-only. Every sandbox's worker
  runs in that container's cgroup, where a sandbox that stops reading 64 downloads holds 80 MiB: give it a CPU request,
  and a memory limit for as many sandboxes as the node can hold.

`gate.sh` proves the whole path with real traffic on a cluster. It runs `vsock-egress check` there, which names the
assumption about AWS's runtime that broke.
