#ifndef _TS_OPT_H_
#define _TS_OPT_H_
#include <stdint.h>

struct ts_local_opt {
    unsigned long remote_ipv4; // convert from remote
    uint16_t remote_port;
    char remote[256]; // store remote server host or ip
    uint16_t port;
    int log_level;
    char crypto_method[32];
    unsigned char key[256];
    uint32_t key_size;
};

struct ts_server_opt {
    uint16_t port;
    int log_level;
    char crypto_method[32];
    unsigned char key[256];
    uint32_t key_size;
};

void ts_parse_local_opt(int argc, char **argv, struct ts_local_opt *config);
void ts_parse_server_opt(int argc, char **argv, struct ts_server_opt *config);

#endif
