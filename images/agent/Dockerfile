# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY api/ api/
COPY cmd/daemon/ cmd/daemon/
COPY internal/ internal/

RUN CGO_ENABLED=0 go build \
      -mod=vendor \
      -ldflags="-s -w" \
      -trimpath \
      -o /agent \
      ./cmd/daemon

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /agent /agent
ENTRYPOINT ["/agent"]
