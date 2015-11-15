#ifndef _TS_SOCKS_H_
#define _TS_SOCKS_H_
#include <stdint.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <unistd.h>
struct ts_sock_ctx;

typedef int (*sock_read) (struct ts_sock_ctx *);
typedef int (*sock_write) (struct ts_sock_ctx *);

struct ts_sock_ctx {
    struct pollfd *fd;
    struct ts_buf buffer;
    size_t buf_size;
    uint32_t send_pos;
    int state;
    struct ts_sock_ctx *peer;
    void *ctx; // could be ts_local_ctx or ts_server_ctx
    sock_read read;
    sock_write write;
};

struct ts_socks {
    struct pollfd *fds;
    struct ts_sock_ctx *socks;
    size_t nfds;
    size_t capfds;
};

struct ts_sock_ctx *ts_add_fd(struct ts_socks *socks, int fd, int e, sock_read r, sock_write w);
size_t ts_remove_fd_by_index(struct ts_socks *socks, int i);

#endif
