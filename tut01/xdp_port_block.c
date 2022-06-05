#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include "../common/parsing_helpers.h"


SEC("xdp_ssh_block")
int xdp_ssh_block_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	__u32 nh_type, ip_type;

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

	/* We only care about TCP packets */
	if (ip_type != IPPROTO_TCP) {
		return XDP_PASS;
	}

	/* Parse TCP header */
	if (parse_tcphdr(&nh, data_end, &tcph) > 0) {
		/* Block Port 22 for ssh */
		if (bpf_ntohs(tcph->dest) == 22) {
			return XDP_DROP;
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";