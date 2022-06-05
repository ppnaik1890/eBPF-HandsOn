#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <linux/types.h>
#include <stdbool.h>

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

struct arguments{
	char *device;
};

#endif /* __COMMON_DEFINES_H */
