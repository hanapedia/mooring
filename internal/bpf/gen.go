package bpf

//go:generate go tool bpf2go -cc clang -target bpfel SnatEgress ../../bpf/snat_egress.c -- -O2 -g -Wall -Werror -Wno-missing-declarations -mcpu=v3 -I../../bpf/headers -I../../.dev-headers
//go:generate go tool bpf2go -cc clang -target bpfel RevnatIngress ../../bpf/revnat_ingress.c -- -O2 -g -Wall -Werror -Wno-missing-declarations -mcpu=v3 -I../../bpf/headers -I../../.dev-headers
//go:generate go tool bpf2go -cc clang -target bpfel RevnatXdp ../../bpf/revnat_xdp.c -- -O2 -g -Wall -Werror -Wno-missing-declarations -mcpu=v3 -I../../bpf/headers -I../../.dev-headers
