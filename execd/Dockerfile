# execd for k8s_sandbox's network transport: the static binary at /execd, plus busybox for the
# init container that copies it into the sandbox Pod.
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.23-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/execd .

FROM public.ecr.aws/docker/library/busybox:1.37-musl
COPY --from=build /out/execd /execd
