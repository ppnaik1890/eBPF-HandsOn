#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>

#include "../common/parsing_helpers.h"

#define MAX_SIZE_PORT_MAP 0xffff

struct bpf_map_def SEC("maps") xdp_port_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u16),
	.max_entries = MAX_SIZE_PORT_MAP,
};

SEC("xdp_snoop_ip")
int xdp_snoop_ip_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;

	/* Declare a pointer to all header structs */
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	__u32 nh_type, ip_type, exists = 1;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Parse Ethernet header */
	nh_type = parse_ethhdr(&nh, data_end, &ethh);

	/* If the packet is not IP, pass it */ 
	if (bpf_ntohs(nh_type) != ETH_P_IP) {
		return XDP_PASS;
	}

	/* Parse IP header */
	ip_type = parse_iphdr(&nh, data_end, &iph);

	/* Check if the packet is TCP */
	if (ip_type != IPPROTO_TCP) {
		return XDP_PASS;
	}

	/* Parse TCP header */
	if (parse_tcphdr(&nh, data_end, &tcph) > 0) {
		/* Retrieve the port from the map */
		__u32 port = bpf_ntohs(tcph->dest);
		/* Set the value to 1 against port in the map which means that we have seen a packet with this port number*/
		if (bpf_map_update_elem(&xdp_port_map, &port, &exists, BPF_ANY) != 0) {
			/* If the update fails, print an error message */
			char fmt[] = "XDP: bpf_map_update_elem failed.\n";
			bpf_trace_printk(fmt, sizeof(fmt));
		}
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
