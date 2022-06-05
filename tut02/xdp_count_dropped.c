#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "../common/parsing_helpers.h"

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct datarec{
	__u32 rx_packets;
	__u32 dropped;
};

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = 1,
};


SEC("xdp_count_dropped_pkts")
int xdp_count_dropped_pkts_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	
	/* Declare a pointer to all header structs */
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	__u32 nh_type, ip_type, key=0;

	struct datarec *rec;
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_ABORTED;

	lock_xadd(&rec->rx_packets, 1);


	/* Start next header cursor position at data start */
	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &ethh);

	if (bpf_ntohs(nh_type) != ETH_P_IP) {
		return XDP_PASS;
	}

	ip_type = parse_iphdr(&nh, data_end, &iph);

	if (ip_type != IPPROTO_TCP) {
		return XDP_PASS;
	}

	if (parse_tcphdr(&nh, data_end, &tcph) > 0) {
		/* Block Port 22 for ssh */
		if (bpf_ntohs(tcph->dest) == 22) {
			lock_xadd(&rec->dropped, 1);
			return XDP_DROP;
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";