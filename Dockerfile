# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 go build \
      -ldflags="-s -w" \
      -trimpath \
      -o /moorctl \
      ./cmd/moorctl

FROM alpine:3.22
COPY --from=builder /moorctl /usr/local/bin/moorctl
ENTRYPOINT ["moorctl"]
