This devcontainer include tools such as minikube and Helm which are required for
Kubernetes Sandbox Environment development and testing.

It is used by the CI pipeline. Its use is optional for local development.

The execd tests connect to pod IPs: before running them, route the pod network to
minikube from outside the devcontainer, as `.github/workflows/test.yml` does.
