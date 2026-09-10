# Cleanup

## Temporary sandboxes

Use `K8sSandboxEnvironment.create()` when a sandbox is needed only for part of a
sample, such as an intermediate scoring call:

```python
from k8s_sandbox import K8sSandboxEnvironment


async def grade(submission: str) -> str:
    async with K8sSandboxEnvironment.create(
        "grading", "scoring.compose.yaml", {}, cleanup_timeout=60
    ) as environments:
        scoring = environments["default"]
        await scoring.write_file("/tmp/submission.txt", submission)
        result = await scoring.exec(["python", "/grade.py", "/tmp/submission.txt"])
        if not result.success:
            raise RuntimeError(result.stderr)
        return result.stdout
```

Each call creates a new release and waits for its sandboxes to be ready. All
services in the supplied configuration live until the context exits; use a
configuration containing only the scoring workload and its dependencies. With
the built-in chart, name the scoring service `default` to replace the chart's
default Python service.

Use the returned handles directly. The context does not change the sample's
existing sandboxes or register new ones with Inspect's `sandbox()`. It does not
copy `Sample.files`, run `Sample.setup`, record Inspect `SandboxEvent` entries,
or acquire Inspect's `max_sandboxes` limit. Upload inputs and run setup through
the returned handles, and bound concurrent calls separately. The supplied
configuration must include any deployment-specific policies and labels needed
by these additional sandboxes.

The context removes its release on success, errors, and cancellation, including
cancellation during installation. `cleanup_timeout` must be positive and finite
and defaults to 60 seconds. After expiry, stopping Helm and collecting its output
each allow up to 5 additional seconds. Cleanup failure raises when the block
succeeded; if the block or installation already failed, that error is preserved
and the cleanup failure is logged. Failed cleanup remains tracked. When the
enclosing Inspect eval already initialized the k8s provider and sandbox cleanup
is enabled, its final cleanup retries removal. Otherwise, use the CLI cleanup
commands below to retry a failed removal. The context always attempts cleanup,
including when the enclosing eval uses `--no-sandbox-cleanup`.

## Releases left behind

If the Inspect process were to terminate unexpectedly, it may leave behind resources in
the Kubernetes cluster. To see if any Helm releases have been left behind, either use
K9s and type `:helm` followed by enter, or use the Helm CLI:

```sh
helm list
```

To uninstall all of the Inspect-managed Helm releases:

```sh
inspect sandbox cleanup k8s
```

This will list all of the Inspect-managed Helm releases (it will infer whether they are
Inspect-managed based on the labels) in the current namespace and offer to uninstall
them all for you.

!!! warning
    This command will find and uninstall all Inspect-managed Helm releases **for any
    user of the Kubernetes namespace**. If you are using a shared Kubernetes namespace,
    please be careful when choosing which Helm releases to uninstall.
