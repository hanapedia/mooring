# syntax=docker/dockerfile:1
FROM nixos/nix AS builder

RUN echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

WORKDIR /src

# Copy flake first so the nix store layer is cached until the flake changes.
COPY flake.nix flake.lock ./
RUN nix develop --command echo "dev shell ready"

# Download modules before copying source for better layer caching.
COPY go.mod go.sum ./
RUN nix develop --command go mod download

COPY Taskfile.yaml ./
COPY api/ api/
COPY bpf/ bpf/
COPY cmd/daemon/ cmd/daemon/
COPY internal/ internal/

RUN <<'EOF'
nix develop --command sh -c '
  task gen-vmlinux &&
  task gen-dev-headers &&
  task generate &&
  CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /agent ./cmd/daemon
'
EOF

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /agent /agent
ENTRYPOINT ["/agent"]
