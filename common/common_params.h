/* This common_user.h is used by userspace programs */
#ifndef __COMMON_PARAMS_H
#define __COMMON_PARAMS_H

#include "common_defines.h"


void usage(const char *prog_name);

void parse_cmdline_args(int argc, char **argv,struct arguments *args);

#endif /* __COMMON_PARAMS_H */