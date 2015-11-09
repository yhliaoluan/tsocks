#ifndef _TS_OPT_H_
#define _TS_OPT_H_
#include <stdint.h>

struct ts_local_opt {
    uint16_t port;
    int loglevel;
};

void ts_parse_local_opt(int argc, char **argv, struct ts_local_opt *config);

#endif
