#pragma once

/* TC action codes — linux/pkt_cls.h */
#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_RECLASSIFY
#define TC_ACT_RECLASSIFY 1
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif
#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE 3
#endif
#ifndef TC_ACT_STOLEN
#define TC_ACT_STOLEN 4
#endif
#ifndef TC_ACT_QUEUED
#define TC_ACT_QUEUED 5
#endif
#ifndef TC_ACT_REPEAT
#define TC_ACT_REPEAT 6
#endif
#ifndef TC_ACT_REDIRECT
#define TC_ACT_REDIRECT 7
#endif
#ifndef TC_ACT_TRAP
#define TC_ACT_TRAP 8
#endif

/* Ethernet — linux/if_ether.h */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif
#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* IP protocols — linux/in.h */
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

/* BPF map update flags — linux/bpf.h */
#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif
#ifndef BPF_EXIST
#define BPF_EXIST 2
#endif

/* BPF map creation flags — linux/bpf.h */
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

/* Flags for bpf_l4_csum_replace — linux/bpf.h */
#ifndef BPF_F_MARK_MANGLED_0
#define BPF_F_MARK_MANGLED_0 (1ULL << 3)
#endif
#ifndef BPF_F_PSEUDO_HDR
#define BPF_F_PSEUDO_HDR (1ULL << 4)
#endif
#ifndef BPF_F_MARK_ENFORCE
#define BPF_F_MARK_ENFORCE (1ULL << 6)
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif
