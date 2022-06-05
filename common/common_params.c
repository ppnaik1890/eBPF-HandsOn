#include "common_params.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage(const char *prog_name) {
	fprintf(stdout, "usage: %s --dev <device>", prog_name);
}

void parse_cmdline_args(int argc, char **argv, struct arguments *args) {
	if (argc != 3) {
		usage(argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (strcmp(argv[1], "--dev") != 0) {
		usage(argv[0]);
		exit(EXIT_SUCCESS);
	}
	args->device = argv[2];
}
