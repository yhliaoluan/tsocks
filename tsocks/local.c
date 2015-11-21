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

void ts_close_sock(struct ts_sock *sock) {
    event_free(sock->ev);
    shutdown(sock->fd, 2);
    ts_free(sock);
}

void ts_pick_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    char buf[128] = {0};
    if (recv(fd, buf, sizeof(buf), 0) <= 0) {
        ts_close_sock(sock);
        ts_log_d("%d closed", fd);
    } else {
        event_add(sock->ev, NULL);
    }
}

static void ts_tcp_accept(evutil_socket_t fd, short what, void *arg) {
    struct sockaddr_in addr;
    uint32_t size = sizeof(addr);
    int client = accept(fd, (struct sockaddr *) &addr, &size);

    if (client < 0) {
        sys_err("accept error.");
    }

    if (fcntl(client, F_SETFL, fcntl(client, F_GETFL, 0) | O_NONBLOCK) < 0) {
        sys_err("fcntl error.");
    }

    ts_log_d("accept client %d from %s:%u", client,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    struct ts_sock *sock = ts_malloc(sizeof(struct ts_sock));
    memset(sock, 0, sizeof(struct ts_sock));
    sock->fd = client;

    struct event *ev = event_new((struct event_base *)arg, client,
        EV_READ, ts_pick_method, sock);

    sock->ev = ev;
    event_add(ev, NULL);
}

static int ts_create_tcp_sock(struct ts_local_ctx *ctx) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        sys_err("create socket failed.");
    }
    ts_log_d("tcp listener socket fd:%d", fd);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(ctx->config.port);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        sys_err("bind failed.");
    }

    if (listen(fd, 10) < 0) {
        sys_err("listen failed.");
    }

    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
        sys_err("set non-blocking error.");
    }

    return fd;
}

int main(int argc, char **argv) {
    struct ts_local_ctx ctx= { 0 };

    ts_parse_local_opt(argc, argv, &ctx.config);
    ts_set_log_level(ctx.config.log_level);

    ts_log_i("use config: log_level:%s port:%u",
        ts_level2str(ctx.config.log_level), ctx.config.port);
    int fd = ts_create_tcp_sock(&ctx);
    struct event_base *base = event_base_new();
    if (!base) {
        sys_err("create event_base failed.");
    }

    struct event *ev = event_new(base, fd, EV_READ | EV_PERSIST, ts_tcp_accept, base);
    if (event_add(ev, NULL) < 0) {
        sys_err("add event failed");
    }
    
    event_base_dispatch(base);
    event_free(ev);
    event_base_free(base);
    exit(0);
}
