# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY api/ api/
COPY cmd/operator/ cmd/operator/
COPY internal/allocator/ internal/allocator/
COPY internal/controller/operator/ internal/controller/operator/

RUN CGO_ENABLED=0 go build \
      -mod=vendor \
      -ldflags="-s -w" \
      -trimpath \
      -o /operator \
      ./cmd/operator

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /operator /operator
ENTRYPOINT ["/operator"]
