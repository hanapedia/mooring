ARG BIRD_VERSION=latest
FROM --platform=linux/amd64 ghcr.io/cybozu/bird:${BIRD_VERSION}

RUN apt update && \
    apt install -y iproute2 iputils-ping traceroute tcpdump iptables

# We need this path at runtime
RUN mkdir -p /run/bird
