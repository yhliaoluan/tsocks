#ifndef _TS_OPT_H_
#define _TS_OPT_H_
#include <stdint.h>

struct ts_local_opt {
    unsigned long remote_ipv4;
    uint16_t remote_port;
    uint16_t port;
    int log_level;
    int crypto_method;
    unsigned char key[256];
};

struct ts_server_opt {
    uint16_t port;
    int log_level;
    int crypto_method;
    unsigned char key[256];
};

void ts_parse_local_opt(int argc, char **argv, struct ts_local_opt *config);
void ts_parse_server_opt(int argc, char **argv, struct ts_server_opt *config);

#endif
