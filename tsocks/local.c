#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include "utils/log.h"
#include "utils/opt.h"
#include "utils/debug.h"
#include "utils/list.h"
#include "utils/mem.h"
#include "utils/utils.h"

struct ts_local_ctx;

struct ts_sock_ctx {
    struct pollfd *fd;
    struct ts_buf buffer;
    int send_pos;
    struct ts_sock_ctx *peer;
    struct list_head list;
    struct ts_local_ctx *ctx;
    int (*read) (struct ts_sock_ctx *);
    int (*write) (struct ts_sock_ctx *);
};

struct ts_local_ctx {
    struct pollfd *fds;
    uint32_t nfds;
    uint32_t capfds;
    struct ts_sock_ctx head;
    struct ts_local_opt *config;
};

static void ts_add_fd(struct ts_local_ctx *ctx, int fd, int e,
    int (*read) (struct ts_sock_ctx *),
    int (*write) (struct ts_sock_ctx *)) {

    ts_log_d("adding sockfd:%d, events:%d", fd, e);
    if (ctx->capfds == ctx->nfds) {
        ctx->capfds = min(ctx->capfds * 2, 16);
        struct pollfd *oldfds = ctx->fds;
        ctx->fds = malloc(sizeof(struct pollfd) * ctx->capfds);
        memcpy(ctx->fds, oldfds, sizeof(struct pollfd) * ctx->nfds);
        free(oldfds);
    }
    ctx->fds[ctx->nfds].fd = fd;
    ctx->fds[ctx->nfds].events = e;
    ctx->nfds++;

    struct ts_sock_ctx *sock = malloc(sizeof(struct ts_sock_ctx));
    memset(sock, 0, sizeof(struct ts_sock_ctx));
    sock->fd = &ctx->fds[ctx->nfds - 1];
    sock->ctx = ctx;
    sock->read = read;
    sock->write = write;

    list_add(&sock->list, &ctx->head.list);
}

static int ts_client_read(struct ts_sock_ctx *ctx) {
    ts_log_d("sock %d got something to read", ctx->fd->fd);
    char buf[256] = {0};
    int received = recv(ctx->fd->fd, buf, sizeof(buf - 1), 0);
    buf[received] = 0;
    printf("%s", buf);
    return received;
}

static int ts_tcp_read(struct ts_sock_ctx *ctx) {
    ts_log_d("sock %d have a client", ctx->fd->fd);
    struct sockaddr_in addr;
    uint32_t size = sizeof(addr);
    int fd = accept(ctx->fd->fd, (struct sockaddr *) &addr, &size);
    if (fd < 0) {
        sys_err("accept error.");
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        sys_err("fcntl error.");
    }
    ts_log_d("received client from port:%u", ntohs(addr.sin_port));
    ts_add_fd(ctx->ctx, fd, POLLIN, ts_client_read, NULL);
    return 0;
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
    addr.sin_port = htons(ctx->config->port);

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
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &ctx->head.list) {
            struct ts_sock_ctx * sock = list_entry(pos,
                struct ts_sock_ctx, list);
            ts_log_d("fd:%d, events:%d revents:%d", sock->fd->fd, 
                sock->fd->events, sock->fd->revents);
            if (sock->fd->revents & POLLIN) {
                sock->read(sock);
                sock->fd->revents = 0;
            }
        }
    }
}

int main(int argc, char **argv) {

    struct ts_local_opt config = { 0 };

    ts_parse_local_opt(argc, argv, &config);
    struct ts_local_ctx ctx= { 0 };
    INIT_LIST_HEAD(&ctx.head.list);
    ctx.config = &config;
    ts_start_local(&ctx);

    ts_loop(&ctx);
    
    exit(0);
}
