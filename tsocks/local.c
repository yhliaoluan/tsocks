#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include "utils/log.h"
#include "utils/opt.h"
#include "utils/debug.h"
#include "utils/memory.h"
#include "utils/utils.h"
#include "utils/socks.h"

struct ts_local_ctx {
    struct ts_local_opt config;
};

static void ts_write_to_buffer(struct ts_sock_ctx *ctx, unsigned char *buf, size_t size) {
    if (ctx->buf_size == 0) {
        ts_realloc(&ctx->buffer, size);
        memcpy(ctx->buffer.buffer, buf, size);
        ctx->buf_size = size;
    } else {
        ts_alloc(&ctx->buffer, ctx->buf_size + size);
        memcpy(ctx->buffer.buffer + ctx->buf_size, buf, size);
        ctx->buf_size += size;
    }
}

static int ts_print_read_exit(struct ts_sock_ctx *sock) {
    unsigned char buf[512] = {0};
    int received = recv(sock->fd->fd, buf, sizeof(buf), 0);
    ts_log_d("recf %d data", received);
    if (received <= 0) {
        return -1;
    }
    ts_print_bin_as_hex(buf, received);
    return -1;
}

static int ts_client_read(void *ctx, struct ts_sock_ctx *sock) {
    return ts_print_read_exit(sock);
}

static int ts_client_write(void *ctx, struct ts_sock_ctx *sock) {
    return -1;
}

static int ts_accept(void *ctx, struct ts_sock_ctx *sock) {
    struct sockaddr_in addr;
    uint32_t size = sizeof(addr);
    int fd = accept(sock->fd->fd, (struct sockaddr *) &addr, &size);

    if (fd < 0) {
        sys_err("accept error.");
    }

    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        sys_err("fcntl error.");
    }

    ts_log_d("accept client %d from %s:%u", fd,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    struct ts_local_ctx *local = ctx;
    ts_add_fd(&local->socks, fd, POLLIN, ts_client_read, ts_client_write);
    return fd;
}

static void ts_start_local(struct ts_local_ctx *ctx) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        sys_err("create socket failed.");
    }
    ts_log_d("tcp listener socket fd:%d", sockfd);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(ctx->config.port);

    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        sys_err("bind failed.");
    }

    if (listen(sockfd, 10) < 0) {
        sys_err("listen failed.");
    }

    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        sys_err("set non-blocking error.");
    }

    //TODO add to list
}

static void ts_loop(struct ts_local_ctx *ctx) {
    for (;;) {
        if (poll(ctx->socks.fds, ctx->socks.nfds, -1) < 0) {
            sys_err("poll error.");
        }
        int i;
        for (i = ctx->socks.nfds - 1; i >= 0; i--) {
            struct ts_sock_ctx *sock = &ctx->socks.socks[i];
            if (sock->fd->revents & POLLIN) {
                if (sock->read(ctx, sock) < 0) {
                    ts_remove_fd_by_index(&ctx->socks, i);
                    continue;
                }
            }
            if (sock->fd->revents & POLLOUT) {
                if (sock->write(ctx, sock) < 0) {
                    ts_remove_fd_by_index(&ctx->socks, i);
                    continue;
                }
            }
            sock->fd->revents = 0;
        }
    }
}

int main(int argc, char **argv) {
    struct ts_local_ctx ctx= { 0 };

    ts_parse_local_opt(argc, argv, &ctx.config);
    ts_set_log_level(ctx.config.log_level);

    ts_log_i("use config: log_level:%s port:%u",
        ts_level2str(ctx.config.log_level), ctx.config.port);
    ts_start_local(&ctx);

    ts_loop(&ctx);
    
    exit(0);
}
