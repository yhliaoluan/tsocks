#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <event2/event.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include "utils/log.h"
#include "utils/opt.h"
#include "utils/debug.h"
#include "utils/mem.h"
#include "utils/utils.h"
#include "utils/socks.h"

#define STATE_INIT 0
#define STATE_HANDSHAKE_REQ 1
#define STATE_HANDSHAKE_RES 2 
#define STATE_CONNECT_REQ 3
#define STATE_CONNECT_RES 4

struct ts_server_ctx {
    struct ts_socks socks;
    struct ts_server_opt config;
};

static int ts_pickup_methods(const unsigned char *methods, size_t size) {
    while (size-- > 0) {
        if (*methods++ == 0x00) { return 0x00; }
    }
    return 0xFF;
}

static void ts_write_to_buffer(struct ts_sock_ctx *sock, unsigned char *buf, size_t size) {
    if (sock->buf_size == 0) {
        ts_realloc(&sock->buffer, size);
        memcpy(sock->buffer.buffer, buf, size);
        sock->buf_size = size;
    } else {
        ts_alloc(&sock->buffer, sock->buf_size + size);
        memcpy(sock->buffer.buffer + sock->buf_size, buf, size);
        sock->buf_size += size;
    }
}

static int ts_handshake_read(struct ts_server_ctx *ctx, struct ts_sock_ctx *sock) {
    unsigned char buf[512] = {0};
    int received = recv(sock->fd->fd, buf, sizeof(buf), 0);
    if (received < 3) {
        return -1;
    }
    ts_print_bin_as_hex(buf, received);
    if (buf[0] != 0x05 || buf[1] == 0) {
        ts_log_d("invalid greeting request:");
        ts_print_bin_as_hex(buf, received);
        return -1;
    }
    buf[1] = ts_pickup_methods(buf + 2, buf[1]);
    ts_write_to_buffer(sock, buf, 2);
    sock->fd->events |= POLLOUT;
    sock->state = STATE_HANDSHAKE_REQ;
    return received;
}

static int ts_client_read(void *ctx, struct ts_sock_ctx *sock) {
    switch (sock->state) {
    case STATE_INIT:
        return ts_handshake_read(ctx, sock);
    default:
        return -1;
    }
}

static int ts_handshake_write(struct ts_server_ctx *ctx, struct ts_sock_ctx *sock) {
    ts_log_d("client %d enter greeting write", sock->fd->fd);
    ssize_t sent = send(sock->fd->fd, sock->buffer.buffer + sock->send_pos,
        sock->buf_size - sock->send_pos, 0);
    if (sent >= 0) {
        sock->send_pos += sent;
        if (sock->send_pos == sock->buf_size) {
            sock->fd->events &= ~POLLOUT;
            sock->send_pos = sock->buf_size = 0;
        }
    }
    return sent;
}

static int ts_client_write(void *ctx, struct ts_sock_ctx *sock) {
    switch (sock->state) {
    case STATE_HANDSHAKE_REQ:
        return ts_handshake_write(ctx, sock);
    default:
        return -1;
    }
}

static int ts_tcp_read(void *ctx, struct ts_sock_ctx *sock) {
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
    ts_add_fd(&((struct ts_server_ctx *)ctx)->socks, fd, POLLIN, ts_client_read, ts_client_write);
    return fd;
}

static void ts_start_server(struct ts_server_ctx *ctx) {
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

    ts_add_fd(&ctx->socks, sockfd, POLLIN, ts_tcp_read, NULL);
}

static void ts_loop(struct ts_server_ctx *ctx) {
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
    struct ts_server_ctx ctx = { 0 };

    ts_parse_server_opt(argc, argv, &ctx.config);
    ts_set_log_level(ctx.config.log_level);

    ts_start_server(&ctx);

    ts_loop(&ctx);
    return 0;
}
