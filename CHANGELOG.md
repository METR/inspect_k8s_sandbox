# Changelog

## Unreleased

- Once a process has converted one Docker Compose file to Helm values, each further
  conversion takes about 60 to 100 ms less.
- Fix a sandbox rendered inside a typed list such as a `DeploymentList` not being waited
  for; a chart with no other sandbox was refused as declaring none.
- Fix a sandbox being handed over on a Pod that is being deleted. An install waits
  while any Pod of the release is being deleted and has not stopped.
- Fix the install failing with "Could not read the rendered manifest from Helm" when
  one document of a manifest defines a YAML anchor twice.
- Fix a "Helm release did not become ready" error hiding the API error that its last
  check of the Pods failed with: it is now that error's cause.
- **BREAKING CHANGE**: Fail the install as soon as Helm returns when a sandbox is
  declared only by Deployments or StatefulSets at `replicas: 0`, even if something would
  scale one up later. Render each sandbox with at least one replica.
- A sandbox is handed over as soon as its pods are ready, where it took up to 2 s.
  This needs the `watch` verb on Pods; without it a sandbox is handed over as before.
- Fix the Docker Compose conversion failing on a `healthcheck` with `test: []`,
  `test: ["NONE"]` or no `test`: the service gets no readiness probe.
- A compose file given as `values` in `K8sSandboxEnvironmentConfig`, or to
  `convert_compose_to_helm_values`, now converts with `healthcheck.disable`, a quoted
  `healthcheck.retries`, `mem_limit` as a number of bytes, `deploy:` with no value, and
  services that share a YAML alias (the later one lost settings). An unquoted key
  such as `on`, `yes` or `1` fails with a message asking to quote it.
- A `CMD-SHELL` healthcheck `test` passes every item after `CMD-SHELL` to `sh -c`,
  where only the first was kept.
- **BREAKING CHANGE**: A negative `healthcheck.retries`, and a top-level
  `x-inspect_k8s_sandbox` that is a list or a plain value, now fail the conversion. So
  does a file that converted only because a YAML alias between two services, or between
  a service and the top level, hid an error: it fails as it does with the alias written
  out. Where a service reuses the top-level `x-inspect_k8s_sandbox` as its own, move the
  anchor into the first service that uses it.
- A pod annotated
  `inspect-k8s-sandbox/egress-proxy: "<service>.<namespace>.svc.cluster.local:<port>"`
  (a template there can name a Service of the release) gets an HTTP proxy at
  `127.0.0.1:3128` that reaches only that Service of its own namespace, for an AWS Nitro
  Sandbox with no network device. The Service's pods must carry the release's
  `app.kubernetes.io/name` and `app.kubernetes.io/instance` labels and listen on that
  port; those that `additionalResources` adds need policies of their own (see
  `vsock-egress/README.md`). The annotated pod gets none of the release's other egress
  grants (`allowDomains`, `allowCIDR`, `allowEntities`), and its forwarder is a native
  sidecar, which needs Kubernetes 1.29 or later. Set `https_proxy` and `http_proxy`
  yourself (curl reads `http_proxy` in lower case only), their upper-case forms,
  `no_proxy` for a server on the sandbox's own loopback, and the new
  `egressForwarderImage` value. Each node must run `vsock-egress launch` and hold two
  seccomp profiles, which `vsock-egress install` writes (see `vsock-egress/README.md`):
  on a node with no launcher such a pod does not start. The forwarder's container is named
  `egress-forwarder-with-a-name-too-long-for-any-service-to-share`.
- Add `additionalResourceDnsRecords`: a Service that `additionalResources` adds as
  `{{ template "agentEnv.fullname" $ }}-<name>` resolves from within the agent
  environment as `$AGENT_ENV-<name>` once the value lists `<name>`.
- Wait for the Pods of every `apps/v1` StatefulSet of the release, in its namespace,
  whose Pod template carries the release's `app.kubernetes.io/instance` label, including
  those from `additionalResources`, before handing over a sandbox.
- Fix a sandbox failing to start when a value such as a `command` argument is exactly
  `=` or `<<`, or a date or time that does not exist such as `2023-02-29`.
- A service or namespace named `no` or `123`, or a generated release name that reads as
  a number, no longer fails the install, and a label key such as `no` or `on` is no
  longer applied as `false` or `true`.
- **BREAKING CHANGE**: Fail the install when a string inside a block value
  (`securityContext`, `resources`, `nodeSelector`, `tolerations`, `command`, `annotations`
  with the task's name, ...) holds DEL, a C1 control character, U+FFFE or U+FFFF, or one
  of the block's keys is over 1,022 characters as JSON. The block was silently left out,
  or a U+0085 in it turned into a space. A quoted `"<<"` key in such a value fails the
  install too. So do most strings in such a value that hold U+2028 or U+2029.
- A newline in a service's `image`, `runtimeClassName`, `workingDir`, `imagePullPolicy`,
  env name or port `protocol`, in an init container's `name`, `image`, `workingDir`,
  `imagePullPolicy` or env name, or in an `allowDomainsPorts` entry's `protocol`, no
  longer splices a field into the rendered manifest.
- Add a per-service `terminationGracePeriodSeconds` value (default `0`, as before), for a
  runtime whose node must stop a deleted Pod before another Pod takes its room.
- A pod annotated `inspect-k8s-sandbox/execd: "true"`, with execd (built from `execd/`)
  mounted read-only at `/execd/execd` and TCP port 14601 reachable from the client at
  the pod's IP and from no other pod, runs `exec()`, `read_file()`, `write_file()` and
  `exec_stdio()` over TLS to execd instead of Kubernetes exec. There, a command runs as
  a program: a shell builtin such as `cd`, or a name that starts with `-`, is not found,
  its environment holds `HAWK_NEXT_EXEC`, a `cwd` that does not exist ends it with
  status 1, and with no `stdin` it reads end-of-file. Run as another user, it has a
  soft open-file limit of 1024 where the hard limit is no lower, whatever the image's
  PAM limits say, and may raise it to the hard limit. If a symbolic link on the path to
  the container's working directory is re-pointed, a command given no `cwd`, or a
  relative one, still runs where the link pointed when execd started, and ends with
  status 1 once that directory is gone. On a timed-out or cancelled `exec()`, or a
  closed `exec_stdio()` stream, whose command is still running, execd sends SIGTERM, and
  5 seconds later SIGKILL to what has not ended: to the command, to its process group
  and to the other processes it started that it can find, as far as it may signal each;
  one that has detached from the command can survive. A command still being started, or
  one killed when execd has no file descriptor left, gets SIGKILL at once. A timed-out
  `exec()` raises `TimeoutError`, whose `truncated_output` holds what the command wrote,
  once the command and the processes execd signalled have ended or been sent SIGKILL, or
  16 seconds after its timeout at the latest. What they start after their SIGTERM gets
  SIGKILL as soon as they have ended: a handler must wait for the cleanup it starts. (On
  gVisor and on Linux before 6.9, one left in the command's group whose environment no
  longer holds `HAWK_NEXT_EXEC` can run on. On Linux before 6.9 and on gVisor before
  release-20260928.0, a threaded program's SIGTERM handler, as in Python, may not run;
  on gVisor release-20261109.0 it runs.) The processes of a command that has ended by
  itself are left running. Once execd has stopped reading a command's output, 100 ms
  after the command ended at the earliest, what it left running may write 1 MiB more in
  total to each of the command's stdout and stderr, plus that pipe's free space; past
  that a write to it blocks, or fails with EAGAIN where the pipe is non-blocking. execd
  keeps such pipes for at most half of its open-file limit (512 in a Kata guest), and
  past that it closes a further one: the next write to it raises SIGPIPE, or fails with
  EPIPE where that signal is ignored. Both hold where execd holds the pipe's only read
  end. A command that ends execd, as by killing every process, ends each running
  `exec()` as a killed command, with status 137 and the output so far, even one whose
  command had not started; a running `read_file()` or `write_file()` is run again.
  They raise `ExecResultUnknownError` instead (the cause of a `K8sError`;
  `ContainerRestartedError` where a restarted container is set to raise) where the
  call's connection to execd was lost before execd ended, since its command may have
  ended unheard, and where execd cannot be started again or cannot be shown to run in
  the same container (another one, or a pod that sets `shareProcessNamespace` or
  `hostPID`); an `exec()` whose timeout had passed raises `TimeoutError`. A command
  still running, as where execd alone was killed, goes on without its timeout and with
  end-of-file on `stdin`, though its call has ended. Keep execd on a memory-backed
  volume: on the container's disk, a pod thrashing at its memory limit evicts execd's
  code, and a timeout's kill can then take the client's whole 16 seconds and hold up
  the next call. Idle, execd holds 20 to 23 of the pod's PIDs, and needs a PID limit
  of about 30 to start.
  Make execd mode 111; where a container runs on gVisor as a
  user other than root it must be readable too (555). A process running as execd's user
  can stand in for it while it starts, unless execd is mode 111 and the container has
  neither `CAP_DAC_OVERRIDE` nor `CAP_DAC_READ_SEARCH`. execd's memory counts against
  the container's limit: about 7 MB idle, 5 to 16 MB for each stream (stdout, stderr) of
  a command that prints faster than the client reads, and up to about 10 MB for each
  command that leaves its stdin unread, most of it kept for minutes after the command
  ends. With `restarted_container_behavior="raise"`, a pod that sets
  `shareProcessNamespace` or `hostPID` is refused: the sample fails to start.
- Add `inspect-k8s-sandbox/execd: "stdio"` for pods with no network device.
- A pod annotated `sandbox.amazonaws.com/network-isolated: "true"` gets no CoreDNS
  sidecar. A service with a DNS record finds itself there under its own name and its
  `additionalDnsRecords` through `/etc/hosts`, at `127.0.0.1`. The install fails for a
  record that is no lower-case DNS name (upper case, `_`, `*`, a trailing dot), and
  where that line of `/etc/hosts`, the address and every name with a tab between, is
  longer than the 510 bytes musl reads of one.
- Init containers take `env` and `volumeMounts`, so one can write a file into a volume
  the service's container then reads.
- Fix orphaned processes exhausting PID slots in sandboxes using the default
  entrypoint. The default entrypoint requires `sh` and `sleep`. Services explicitly
  configured to run `tail -f /dev/null` still accumulate zombies; they must use the
  reaping loop instead to benefit from this fix. See
  [Init Process](https://k8s-sandbox.aisi.org.uk/helm/compose-to-helm/#init-process).
- A warning is logged when Compose `init: true` is ignored on non-default services
  or on the default service with an explicit `command` or `entrypoint`.
- Fix `read_file()` failing with a `ValidationError` on `kubernetes` 37.
- Add a `priorityClassName` value for the sandbox pods' PriorityClass. It is a cluster
  setting, so set it in the `INSPECT_SANDBOX_VALUES` file.
- Fix `read_file()` hanging on a relative file named `-`.
- Fix `write_file()` over Kubernetes exec never returning when a large file could not
  be written.
- Fix `exec()` over Kubernetes exec never returning when its `user` could not be
  switched to and its command, environment or input was large.
- Fix a sandbox whose generated release name was already in use failing to start and
  uninstalling the release that had the name.
- With `restarted_container_behavior="raise"`, every operation after a detected pod
  replacement or container restart fails with the same `PodReplacedError` or
  `ContainerRestartedError` (as the cause of a `K8sError`), and so does one running when
  it was detected. `read_file()` and `write_file()` do too when
  `INSPECT_POD_RESTART_CHECK=false`. A container that Kubernetes shows stopped, or
  waiting to start again, counts as restarted.
- With `restarted_container_behavior="raise"`, a `read_file()` or `write_file()` over
  Kubernetes exec that fails checks whether the container restarted or the pod was
  replaced, also when `INSPECT_POD_RESTART_CHECK=false`, and raises that instead.
- The pod read that checks for a restart no longer waits without end on an API server
  that sends nothing: the operation fails after about four minutes.
- An operation over Kubernetes exec no longer waits without end on an API server that
  never answers its websocket upgrade: each connection attempt times out after 60
  seconds.
- An operation is tried again when the restart check before an attempt cannot reach the
  API server at once: its connection refused or reset, or no route or name found. A
  check that times out there still fails the operation.
- An operation whose container stopped under it, which Kata reports with exit code 255
  when the VM stopped, raises `ContainerStoppedError`, an `ExecResultUnknownError`:
  `exec()` no longer returns 255 as the command's exit code, and `read_file()` and
  `write_file()` are no longer retried. With `restarted_container_behavior="raise"`, or
  for an `exec()` whose check after it sees the restart, it raises
  `ContainerRestartedError` instead.
- Fix a command that printed `<completed-sentinel-value-N>` making `exec()` return
  before it finished, with exit code `N`, and that marker being left at the end of
  stdout when it arrived in two pieces. `exec()` of a command that leaves a
  background process holding its stdout or stderr open now returns a tenth of a
  second after the command exits.
- `exec()` no longer returns a successful result whose output lost its end on the way.
  That, and a connection to the pod lost while the command runs, are retried,
  so the command may run a second time; if every attempt fails, `exec()` raises
  `ExecResultUnknownError` (a `GetReturncodeError`, as the cause of a `K8sError`). They
  are not retried once the container has restarted or been replaced. A pod with execd
  resumes the command instead and never runs it a second time; if it can't resume, it
  raises `ExecResultUnknownError`, or returns 137 where execd was killed under a call
  still connected to it.
- Images no longer need `sync`, and need `printf` (a shell builtin in dash, bash and
  busybox).
- Add a per-service `podAnnotations` value: annotations for that service's Pod
  alone, over the top-level `annotations`, for a runtime that reads per-pod
  settings from annotations.
- Fix an exec's input, such as a large `write_file()`, going unread after about a minute
  with the `kubernetes` Python client 36 or later.
- Add `exec_stdio()`: with `INSPECT_EXEC_REMOTE_BRIDGE=1` (METR's Inspect fork),
  `exec_remote`'s server-wait requests share one exec per sandbox and user instead of
  taking one each. Needs anyio 4.14 or later. With
  `restarted_container_behavior="raise"`, `exec_stdio()` raises a detected restart
  before starting its command, as `exec()` does, and a stream already open raises
  `anyio.BrokenResourceError` at its next `receive()` or `send()` once a restart is
  found. In that mode, when its stream ends with exit code 255 after the
  command wrote stdout (Kata's status for a command whose VM stopped), the stream ends
  as usual and every later operation fails as after a detected restart. The command
  must not exit 255 itself once it has written.
- `exec(user="root")` no longer needs `id` or `runuser` in the image. In a container
  that is not root, `exec(user="0")` now fails as `exec(user="root")` does, with a
  warning, rather than raising a `RuntimeError` that says the user does not exist.
- `exec()`, `read_file()` and `write_file()` no longer find the programs they run
  besides the caller's command through the image's `PATH`: `exec(user=...)` runs
  `runuser` as `/sbin/runuser`, and `id`, `base64`, `timeout`, `head`, `mkdir`, `cat` (and
  `printf`, where the shell has no builtin) come from `/usr/bin` or `/bin`, so images need
  them there. The caller's command still runs with the container's `PATH`.
- The task name and sample UUID reach the chart verbatim, as strings, whatever
  characters they contain (a comma, `=`, a leading `{`, or a name such as `123`).

## 2026-10-09 0.14.0

- `INSPECT_POD_RESTART_CHECK=false` skips the pre-operation pod read inside
  `read_file()` / `write_file()`, for deployments where that per-op
  `read_namespaced_pod` call becomes a load problem on the Kubernetes API server at
  high concurrency. Defaults to enabled, so behaviour is unchanged unless set.
  `exec()` always performs the check regardless.
- Add `networkPolicy.enabled` (default `true`). Set `false` to install on a cluster
  without Cilium; the cluster or pod runtime must then enforce egress and isolation.
  Allowlists, `networks` and `networkIsolated` (compose `network_mode: none`) are
  rejected while it is off.
- `INSPECT_SANDBOX_VALUES=/path/to/values.yaml` applies a Helm values file to every
  install of the built-in chart, after and overriding the task's own values, for
  cluster-wide settings such as `networkPolicy.enabled`, `corednsUpstream` and
  `extraContainers`. Compose tasks pick it up too.
- A sandbox no longer counts as ready while its CoreDNS sidecar is failing to start,
  so a broken DNS configuration fails the install instead of the sample's name lookups.
  The sidecar's startup probe listens on the pod IP at `corednsReadyPort` (default
  `18181`); change it if a service in the pod uses that port.
- Fix `read_file()` hanging or returning a truncated file on Kata Containers' Go runtime
  shim (`kata-qemu`).
- A new `extraContainers` value adds containers, as written, to every service's pod,
  for a runtime that needs a helper in the pod beside the service.
- The CoreDNS sidecar's `Corefile` is now mounted as a directory rather than with
  `subPath`. A new `corednsUpstream` value (a list of DNS server IPs, e.g. the cluster
  DNS Service IP) replaces the `/etc/resolv.conf` `subPath` mount with
  `dnsPolicy: None`, for container runtimes that cannot mount a single file with
  `subPath`. Init containers cannot resolve names in that mode.
- `network_mode: none` isolation is now enforced by omitting any ingress allow for the
  service rather than an unconditional ingress deny. Observable behaviour is unchanged
  for a chart used on its own, but a network policy layered on top of this chart (e.g.
  to allow a specific port) now takes effect instead of being silently shadowed.
- Sandbox pods no longer see their Kubernetes namespace. The kubelet was writing the
  pod's `<pod>.<subdomain>.<namespace>.svc.cluster.local` FQDN into `/etc/hosts`, so an
  agent under evaluation could read whatever the namespace name gives away (e.g. the
  model or benchmark being run). Pods no longer have a subdomain, so the kubelet writes
  a plain `<pod IP> <pod name>` instead. Service-to-service DNS is unaffected. The
  per-pod DNS name `<pod>.<service>.<namespace>.svc.cluster.local` no longer resolves —
  nothing in this chart used it, but a deployment that created its own governing
  Service to reach individual pods by name must now use the pod IP.

- **BREAKING CHANGE**: The CoreDNS sidecar now runs as UID/GID 65532 on a read-only root
  filesystem with only `NET_BIND_SERVICE`. A custom `corednsImage` must run under that
  context; set the new `corednsSecurityContext` if it cannot. The default image moves
  from CoreDNS 1.8.3 to a digest-pinned CoreDNS 1.14.6.
- **BREAKING CHANGE**: Service names, network names and `additionalDnsRecords` are now
  validated at install time and rejected with a schema error, rather than producing a
  release that fails later or resolves unexpectedly.
- The CoreDNS sidecar no longer serves its `ready` endpoint on port 8181, and refuses
  queries beyond 1000 concurrent.
- Raise an error when a conflicting `max_pod_ops` setting would otherwise be ignored.
- Fix a service's `args` (compose `command:`) reaching the container as a single
  space-joined string instead of a list.
- Honour compose `command:` on the `default` service. Previously the chart default
  entrypoint (`tail -f /dev/null`) was deep-merged in, so the user's command never ran.
- `exec(user=...)` no longer wraps the shell in `runuser` when the container is already
  running as that user. `runuser` calls `setgroups(2)`, which needs `CAP_SETGID` even
  for a root -> root switch, so the unconditional wrapper made every `exec(user=...)`
  fail in a container whose capabilities had been dropped. On that path the process
  environment is the container's rather than one `runuser` has reset (`HOME`, `USER`,
  supplementary groups). A container that cannot switch users at all -- non-root, no
  `CAP_SETGID`, or no `runuser` installed -- is now logged as a warning and returned as
  a failed `ExecResult` rather than raised, so a caller that probes with a user and
  falls back (as inspect-ai does when injecting its sandbox tools) can do so. Naming a
  user that does not exist still raises.
- Map Compose `no-new-privileges` (`security_opt`), including the bare flag, to
  Kubernetes `allowPrivilegeEscalation: false`.
- A sandbox waiting for cluster capacity no longer blocks other sandboxes from being
  created. Inspect's console count of in-progress installs now reflects submissions in
  flight rather than sandboxes still starting up.
- A release which does not become ready now reports `Helm release did not become ready
  within Ns` together with the state of its containers, rather than Helm's
  `context deadline exceeded`. It names the sandboxes still missing, and reports
  Warning events against the rest of the release rather than only its pods, so a
  controller which cannot create its pod at all (a missing `RuntimeClass`, say) is
  explained rather than merely counted as absent.
- A timeout now always reports, rather than hanging, when the Kubernetes API is slow to
  answer the reads which gather the error's diagnostics.
- Charts which render Pods directly, rather than via a StatefulSet or Deployment, are
  now waited for. The eval no longer starts before every Pod labelled `inspect/service`
  is Ready, even when the chart also creates Pods which are not sandboxes — a
  `DaemonSet`, a hook, or anything added through `additionalResources`.
- A chart which declares no Pod labelled `inspect/service` now fails the install,
  rather than starting an eval with no sandbox.
- Fix a sandbox being backed by a pod which had already terminated, when the cluster
  still listed it beside its replacement. `exec()` failed intermittently.
- Add `INSPECT_HELM_UNINSTALL_TIMEOUT` (default 600s). Uninstalls previously used
  `INSPECT_HELM_TIMEOUT`, which is now safe to set to hours.
- A Helm release which fails to uninstall during sample cleanup no longer fails the
  sample. It is retried and reported at the end of the eval as before.
- Remove the `No GPU node is currently available` warning, which also fired for
  releases that requested no GPU.
- Fix sandbox pods being left in the cluster when a sample's sandbox fails to start
  (e.g. `helm install` timing out): every retry of the sample added another set of
  pods, none of which were removed until the eval ended. A chart with fixed-name
  `additionalResources` no longer fails the retry with `exists and cannot be imported
  into the current release`.
- Fix startup failing with `... is not valid SemVer string`.

## 2026-08-12 0.13.0

- Fix `write_file()` silently writing a truncated or empty file while reporting success
- `inspect sandbox cleanup k8s` (with no release name) now **exits non-zero** if any release fails to uninstall, rather than reporting `Complete.` and exiting 0. Releases which fail to uninstall are named, at end-of-task cleanup too, along with their namespace and the `inspect sandbox cleanup k8s <release>` command to retry them.
- **BREAKING CHANGE**: Sandbox pods created by the built-in Helm chart no longer mount
  Kubernetes service-account API tokens by default. Set
  `automountServiceAccountToken: true` only for sandboxes that require Kubernetes API
  access. Docker Compose users can set
  `x-k8s.automount_service_account_token: true`.
- **BREAKING CHANGE**: `serviceAccountName` now selects an existing ServiceAccount by
  default. Set `serviceAccountCreate: true` to retain automatic creation by the Helm
  chart.
- Add `service_account_name`, `service_account_create`, and
  `automount_service_account_token` to the top-level Docker Compose `x-k8s` extension.
- On Helm install failure, the raised error now includes pod diagnostics.
- Compose to HELM: Support the `security_opt` seccomp option (mapped to a pod `seccompProfile`) and ignore the unsupported `memswap_limit`. See [Compose to Helm](https://k8s-sandbox.aisi.org.uk/helm/compose-to-helm/) for details.
- The package and bundled `agent-env` chart versions are now unified, both jumping to
  `0.13.0` (intervening numbers are unused).

## 2026-06-25 0.6.1

- no changes - version bump only

## 2026-06-25 0.6.0

- Replace non-UTF-8 bytes in command output rather than throwing `UnicodeDecodeError`.
- **BREAKING CHANGE**: `allowDomains` egress is now restricted to ports 80/443, with the request identity enforced (TLS SNI on 443, HTTP `Host` on 80) rather than just the resolved IP. Wildcard entries require Cilium >= 1.18. New `allowDomainsPorts` opens other ports to those domains (IP-pinned; see `values.yaml`).
- Add a per-service `x-inspect_k8s_sandbox.resources` compose extension (alias `x-k8s`) for Kubernetes resource `requests`/`limits` (e.g. `ephemeral-storage`) that the `mem_limit`/`cpus`/`deploy.resources` shortcuts cannot express. Merged with those shortcuts; conflicts are rejected.
- Add optional `serviceAccountName` to the agent-env Helm chart for IRSA-based S3 access from sandbox pods.
- Honour Inspect sandbox config overrides (e.g. exec output size limits) that were previously ignored on Kubernetes.
- Recover from pod replacement or container restart instead of looping against the old pod, and raise typed `PodReplacedError` / `ContainerRestartedError` (was `RuntimeError`).
- Include the cause's type and message in `K8sError`'s string.
- Don't misreport a user command's own stderr as a `runuser` configuration error under `exec(user=...)`.
- Fix `exec(input=...)` and `write_file` failing with "Connection reset by peer" for large inputs (e.g. a ~28 MiB binary).
- Fix `TimeoutError`s in high-concurrency evals (many concurrent clusters).

## 2026-05-07 0.5.0

- Fixes for transient errors in sandbox operations
- Prefer kubeconfig over in-cluster config to preserve the configured namespace
- Configurable K8s client token refresh
- Add `INSPECT_K8S_DEFAULT_NAMESPACE` env var to override the default namespace
- Use `--wait=legacy` with Helm 4.x to avoid kstatus treating unscheduled pods as permanently failed
- Log a warning when no GPU node is available during `helm install`, so users know the wait is expected rather than a hang
- Pass comma-separated `key=value` labels from env var `INSPECT_HELM_LABELS` to `helm install --labels`

## 2026-03-04 0.4.0

- `INSPECT_SANDBOX_COREDNS_IMAGE` override
- Detect in-cluster Kubernetes config automatically, falling back to kubeconfig
- Add `max_pod_ops` to `K8sSandboxEnvironmentConfig`
- Declare K8sSandboxEnvironment as Docker-compatible (supports `inspect-harbor` and Docker Compose/Dockerfile config files)
- Pass sample metadata as Helm `--set-string` values
- Extend compose-to-helm converter: support `allow_entities`, ignore `networks[].internal`, default `networks[].driver` to `bridge`
- Add `inspectSampleUUID` label to pods
- Network policy: also allow node-local DNS cache
- Support initContainers

## 2025-12-09 0.3.0

- Increase files open limit if necessary
- Migrate to uv
- Add (ignored) concurrency param to exec
- Support `network_mode: none` in Docker Compose files
- Support `x-default` service key in Docker Compose files
- **Breaking**: When converting multi-service Docker Compose files without an explicit
  default, the first service (in YAML order) is now renamed to `default`. This ensures
  consistent default service resolution regardless of Kubernetes pod ordering.
- **Breaking**: Add validation for null values in Helm values files (Helm 4 silently filters out null values from maps during template processing, which can cause unexpected behavior)

## 2025-09-25 0.2.0

- First release to Pypi
- Ignore `x-local` key in Docker Compose files (Inspect-specific extension).
- Enhanced `additionalResources` to support full Helm templating.
- Support `user` parameter on `K8sSandboxEnvironment.exec()` (only when container is running as root and `runuser` is installed).
- Support `user` parameter on `K8sSandboxEnvironment.connection()` (returns `SandboxConnection`).
- Add `SandboxConnection` support for human agent baselining and connecting to a sandbox for debugging.
- Add support for specifying a kubeconfig context name in K8sSandboxEnvironmentConfig.
- Add automatic translation of Docker Compose files to Helm values files.
- Handle cancellation of evals (either manually or due to an error) such that Helm releases are uninstalled.
- Increase default Helm install timeout from 5 to 10 minutes.
- For "helm install timeout" errors, add link to docs within and include instructions on increasing timeout within the error message.
- Ignore "release not found" errors when uninstalling Helm charts (expected when helm release was not successfully installed).
- Prevent DNS exfiltration attacks by limiting which domains can be looked up (when using the built-in Helm chart).
- If a namespace is not includes in the kubeconfig context, default to a namespace named "default".
- Add `CLUSTER_DEFAULT` magic string for `runtimeClassName` which will remove the field from the pod spec.
- Add ignored `timeout_retry` parameter to `exec()` method.
- Always capture the output of `helm uninstall` so that errors can contain meaningful information.
- Add support for `inspect sandbox cleanup k8s` command to uninstall all Inspect Helm charts.
- Remove use of Inspect's deleted `SANDBOX` log level in favour of `trace_action()` and `trace_message()` functions.
- Initial release.
