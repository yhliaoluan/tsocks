#ifndef _TS_SOCKS_H_
#define _TS_SOCKS_H_
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include "utils/list.h"

struct ts_sock_ctx {
    int fd;
    struct ts_buf buffer;
    size_t buf_size;
    uint32_t send_pos;
    struct list_head list;
    struct ts_sock_ctx *peer;
};

#endif
