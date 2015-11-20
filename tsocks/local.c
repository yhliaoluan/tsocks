#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <event2/event.h>
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

static int ts_tcp_accept(void *ctx, struct ts_sock_ctx *sock) {
    struct sockaddr_in addr;
    uint32_t size = sizeof(addr);
    int fd = accept(sock->fd, (struct sockaddr *) &addr, &size);

    if (fd < 0) {
        sys_err("accept error.");
    }

    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        sys_err("fcntl error.");
    }

    ts_log_d("accept client %d from %s:%u", fd,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    return fd;
}

static int ts_create_tcp_sock(struct ts_local_ctx *ctx) {
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

    return sockfd;
}

int main(int argc, char **argv) {
    struct ts_local_ctx ctx= { 0 };

    ts_parse_local_opt(argc, argv, &ctx.config);
    ts_set_log_level(ctx.config.log_level);

    ts_log_i("use config: log_level:%s port:%u",
        ts_level2str(ctx.config.log_level), ctx.config.port);
    int fd = ts_create_tcp_sock(&ctx);
    
    exit(0);
}
