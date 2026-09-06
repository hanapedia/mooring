# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 go build \
      -mod=vendor \
      -ldflags="-s -w" \
      -trimpath \
      -o /moorctl \
      ./cmd/moorctl

FROM scratch
COPY --from=builder /moorctl /moorctl
ENTRYPOINT ["/moorctl"]
