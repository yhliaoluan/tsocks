#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include "utils/log.h"
#include "utils/opt.h"
#include "utils/debug.h"
#include "utils/mem.h"
#include "utils/utils.h"

#define STATE_CONN 0
#define STATE_GREETING 1
#define STATE_GREETED 2

struct ts_local_ctx;

struct ts_sock_ctx {
    struct pollfd *fd;
    struct ts_buf buffer;
    size_t buf_size;
    uint32_t send_pos;
    int state;
    struct ts_sock_ctx *peer;
    struct ts_local_ctx *ctx;
    int (*read) (struct ts_sock_ctx *);
    int (*write) (struct ts_sock_ctx *);
};

struct ts_local_ctx {
    struct pollfd *fds;
    struct ts_sock_ctx *socks;
    uint32_t nfds;
    uint32_t capfds;
    struct ts_local_opt config;
};

static void ts_remove_fd_by_index(struct ts_local_ctx *ctx, int index) {
    ts_log_d("remove sock %d, count %u", ctx->fds[index].fd, ctx->nfds - 1);
    shutdown(ctx->fds[index].fd, 2);
    ts_free(&ctx->socks[index].buffer);
    ctx->fds[index] = ctx->fds[ctx->nfds - 1];
    ctx->socks[index] = ctx->socks[ctx->nfds - 1];
    ctx->nfds--;
}

static void ts_add_fd(struct ts_local_ctx *ctx, int fd, int e,
    int (*read) (struct ts_sock_ctx *),
    int (*write) (struct ts_sock_ctx *)) {

    if (ctx->capfds == ctx->nfds) {
        ctx->capfds = max(ctx->capfds * 2, 16);

        ts_log_d("resize capability to %u", ctx->capfds);
        struct pollfd *oldfds = ctx->fds;
        ctx->fds = malloc(sizeof(struct pollfd) * ctx->capfds);
        memcpy(ctx->fds, oldfds, sizeof(struct pollfd) * ctx->nfds);
        free(oldfds);

        struct ts_sock_ctx *oldsocks = ctx->socks;
        ctx->socks = malloc(sizeof(struct ts_sock_ctx) * ctx->capfds);
        memcpy(ctx->socks, oldsocks, sizeof(struct ts_sock_ctx) * ctx->nfds);
        free(oldsocks);
    }

    memset(&ctx->fds[ctx->nfds], 0, sizeof(struct pollfd));
    ctx->fds[ctx->nfds].fd = fd;
    ctx->fds[ctx->nfds].events = e;
    ctx->fds[ctx->nfds].revents = 0;

    struct ts_sock_ctx *sock = &ctx->socks[ctx->nfds];
    memset(sock, 0, sizeof(struct ts_sock_ctx));
    sock->fd = &ctx->fds[ctx->nfds];
    sock->state = STATE_CONN;
    sock->ctx = ctx;
    sock->read = read;
    sock->write = write;
    ctx->nfds++;
    ts_log_d("added sock %d, events %d, current count is %u", fd, e, ctx->nfds);
}

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
    ctx->fd->events |= POLLOUT;
}

static unsigned char ts_pickup_methods(const unsigned char *methods, size_t size) {
    while (size-- > 0) {
        if (*methods++ == 0x00) { return 0x00; }
    }
    return 0xFF;
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

static int ts_greeting_read(struct ts_sock_ctx *sock) {
    ts_log_d("client %d enter greeting read", sock->fd->fd);
    unsigned char buf[512] = {0};
    int received = recv(sock->fd->fd, buf, sizeof(buf), 0);
    if (received <= 0) {
        return -1;
    }
    ts_print_bin_as_hex(buf, received);
    if (buf[0] != 0x05 || buf[1] == 0) {
        int *ptr = (int *) buf;
        ts_log_d("invalid greeting request for client %d, 0x%08X 0x%08X",
            sock->fd->fd, *ptr, *(ptr + 1));
        return -1;
    }
    buf[1] = ts_pickup_methods(buf + 2, buf[1]);
    ts_write_to_buffer(sock, buf, 2);
    sock->state = STATE_GREETING;
    return received;
}

static int ts_greeted_read(struct ts_sock_ctx *sock) {
    unsigned char buf[512] = {0};
    int received = recv(sock->fd->fd, buf, sizeof(buf), 0);
}

static int ts_greeting_write(struct ts_sock_ctx *sock) {
    ts_log_d("client %d enter greeting write", sock->fd->fd);
    ssize_t sent = send(sock->fd->fd, sock->buffer.buffer + sock->send_pos,
        sock->buf_size - sock->send_pos, 0);
    if (sent >= 0) {
        sock->send_pos += sent;
        if (sock->send_pos == sock->buf_size) {
            sock->fd->events &= ~POLLOUT;
            sock->state = STATE_GREETED;
            sock->send_pos = sock->buf_size = 0;
        }
    }
    return sent;
}

static int ts_client_read(struct ts_sock_ctx *sock) {
    switch (sock->state) {
    case STATE_CONN:
        return ts_greeting_read(sock);
    case STATE_GREETED:
        return ts_greeted_read(sock);
    default:
        ts_log_e("%d unknown state %d for readingd", sock->fd->fd, sock->state);
        return ts_print_read_exit(sock);
    }
}

static int ts_client_write(struct ts_sock_ctx *sock) {
    switch (sock->state) {
    case STATE_GREETING:
        return ts_greeting_write(sock);
    default:
        ts_log_e("%d unknown state %d for writing", sock->fd->fd, sock->state);
        return -1;
    }
}

static int ts_tcp_read(struct ts_sock_ctx *sock) {
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
    ts_add_fd(sock->ctx, fd, POLLIN, ts_client_read, ts_client_write);
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

    ts_add_fd(ctx, sockfd, POLLIN, ts_tcp_read, NULL);
}

static void ts_loop(struct ts_local_ctx *ctx) {
    for (;;) {
        if (poll(ctx->fds, ctx->nfds, -1) < 0) {
            sys_err("poll error.");
        }
        int i;
        for (i = ctx->nfds - 1; i >= 0; i--) {
            struct ts_sock_ctx *sock = &ctx->socks[i];
            if (sock->fd->revents & POLLIN) {
                if (sock->read(sock) < 0) {
                    ts_remove_fd_by_index(ctx, i);
                    continue;
                }
            }
            if (sock->fd->revents & POLLOUT) {
                if (sock->write(sock) < 0) {
                    ts_remove_fd_by_index(ctx, i);
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
    ts_set_loglevel(ctx.config.loglevel);

    ts_log_i("use config: loglevel:%s port:%u",
        ts_level2str(ctx.config.loglevel), ctx.config.port);
    ts_start_local(&ctx);

    ts_loop(&ctx);
    
    exit(0);
}
