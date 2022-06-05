#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <err.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../common/common_defines.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_params.h"

static int ifindex = -1;
static char ifname[IFNAMSIZ + 1];
static int prog_id;
static int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
static int map_fd;

/*
* Map name should be same as the one used in the BPF program.
*/
static char map_name[] = "xdp_stats_map"; 

/*
* Object file that conatins our BPF program.
*/
static char prog_filename[] = "xdp_count_dropped.o";


static void int_exit(int sig) {
	xdp_link_detach(ifindex, xdp_flags, prog_id);
	exit(EXIT_SUCCESS);
}


int main(int argc, char *argv[]) {
	
	struct arguments args = {};
	parse_cmdline_args(argc, argv, &args);

	int err = 0, prog_fd;

	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = prog_filename,
	};

	struct bpf_prog_info info = {};
	struct bpf_object *obj;

	unsigned int info_len = sizeof(info);

	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
				prog_filename, err, strerror(-err));
		exit(EXIT_FAILURE);
	}

	if (prog_fd < 0) {
		fprintf(stderr, "ERR: bpf_prog_load_xattr: %s\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}
    
    map_fd = init_map_fd(obj, map_name);
	if (map_fd < 0) {
		fprintf(stderr, "bpf_object__find_map_fd_by_name failed on %s: %s\n",
                map_name, strerror(-map_fd));
		exit(EXIT_FAILURE);
	}

     /* Unload XDP program on termination of userspace program*/
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	/* Get a reference to the network device */
	strncpy(ifname, args.device, IFNAMSIZ);
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		fprintf(stderr,
				"ERR: --dev name unknown err(%d):%s\n",
				errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Attach XDP program to device */
	if (xdp_link_attach(ifindex,  xdp_flags, prog_fd) < 0) {
		fprintf(stderr, "link set xdp fd failed\n");
		exit(EXIT_FAILURE);
	}

	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr,"can't get prog info - %s\n", strerror(errno));
		xdp_link_detach(ifindex, xdp_flags, prog_id);
		exit(EXIT_FAILURE);
	}

	/* Save the program ID for future use whiule detaching XDP program*/
	prog_id = info.id;

	struct datarec{
		__u32 rx_packets;
		__u32 dropped;
	} rec;

	__u32 key = 0;
	while (true) {
		err = bpf_map_lookup_elem(map_fd, &key, &rec);
		if(err){
			fprintf(stderr,"bpf_map_lookup_elem failed - %s\n", strerror(errno));
			xdp_link_detach(ifindex, xdp_flags, prog_id);
			exit(EXIT_FAILURE);
		}
		fprintf(stdout,"rx_packets:%u, dropped:%u\n",rec.rx_packets,rec.dropped);
		sleep(2);
	}
	return 0;
}
