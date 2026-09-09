#include "vmlinux.h"

struct nat_key {
  __be32 pod_ip;
  __be16 nat_port;
  __be32 server_ip;
  __be16 server_port;
  __u8 proto;
  __u8 pad[3]; /* verifier does not allow uninitialized bytes */
};

struct nat_val {
  __be16 pod_port;
};

struct lpm_key {
  __u32 prefixlen;
  __be32 addr;
};
