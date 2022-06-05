#include <linux/if_link.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "../common/parsing_helpers.h"

#define MAX_SIZE_PORT_MAP 0xffff


struct bpf_map_def SEC("maps") xdp_port_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u16),
	.max_entries = MAX_SIZE_PORT_MAP,
};


SEC("xdp_snoop_ip")
int xdp_snoop_ip_func(struct xdp_md *ctx) {
	// void *data_end = (void *)(long)ctx->data_end;
	// void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	// struct hdr_cursor nh;
	
    /* Start your code here */
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
