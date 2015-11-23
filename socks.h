#ifndef _TS_SOCKS_H_
#define _TS_SOCKS_H_

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <event2/event.h>
#include "io.h"

struct ts_sock {
    int fd;
    struct ts_buf buffer;
    size_t buf_size;
    uint32_t send_pos;
    struct ts_sock *peer;
    struct event *ev;
};

#endif
