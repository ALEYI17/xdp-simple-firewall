//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";
#define ETH_P_IP 0x0800  // IPv4 EtherType

enum ip_status {
    ALLOW = 0,
    DENY = 1
};

struct ip_entry{
  enum ip_status status;
  __u32 ip;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct ip_entry);
  __uint(max_entries,256);
} block_list SEC(".maps");

const struct ip_entry *unused __attribute__((unused));
const enum ip_status *unused2 __attribute__((unused));
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);
	return 1;
}

SEC("xdp")
int filter_xdp(struct xdp_md *ctx){
  __u32 ip;
  if (!parse_ip_src_addr(ctx,&ip)){
    return XDP_PASS;
  }
  
  bpf_printk("Extracted IP: %u.%u.%u.%u",
    (bpf_ntohl(ip) >> 24) & 0xFF,
    (bpf_ntohl(ip) >> 16) & 0xFF,
    (bpf_ntohl(ip) >> 8) & 0xFF,
    bpf_ntohl(ip) & 0xFF);

  struct ip_entry *ie;
  ie = bpf_map_lookup_elem(&block_list, &ip);
  if(ie && ie->status == DENY)
    return XDP_DROP;
  
  return XDP_PASS;
}
