# vsock-egress at /vsock-egress: the forwarder's container in a sandbox pod, and the launcher's on the node.
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26-alpine@sha256:30b1e546a9c7fa3b747c2bdba3a0c7bdf3a02ebb4c5b8405d2f948d7e8aac4ec AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/vsock-egress .

FROM scratch
COPY --from=build /out/vsock-egress /vsock-egress
ENTRYPOINT ["/vsock-egress"]
