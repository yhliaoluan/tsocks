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
#include "log.h"
#include "opt.h"
#include "debug.h"
#include "memory.h"
#include "utils.h"
#include "socks.h"

struct ts_server_ctx {
    struct ts_server_opt config;
};

void ts_close_sock(struct ts_sock *sock) {
    event_free(sock->ev);
    shutdown(sock->fd, 2);
    ts_free(sock);
    ts_log_d("%d closed", sock->fd);
}

//FIXME really need this?
void ts_reassign_event(struct ts_sock *sock, short what,
    void (*cb) (evutil_socket_t, short, void *), void *arg) {

    struct event_base *base = event_get_base(sock->ev);
    struct event *ev = event_new(base, sock->fd, what, cb, arg);
    event_free(sock->ev);
    sock->ev = ev;
    event_add(ev, NULL);
}

void ts_request_conn(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    unsigned char buf[512];
    if (recv(fd, buf, sizeof(buf), 0) < 10 || buf[1] != 1 || buf[2] != 0) {
        ts_close_sock(sock);
    } else {
        ts_print_bin_as_hex(buf, sizeof(buf));
        ts_close_sock(sock);
    }
}

void ts_response_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    if (send(fd, "\5\0", 2, 0) != 2) {
        ts_close_sock(sock);
    } else {
        ts_reassign_event(sock, EV_READ, ts_request_conn, sock);
    }
}

void ts_request_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    char buf[512];
    if (recv(fd, buf, sizeof(buf), 0) < 2 || buf[0] != 5) {
        ts_close_sock(sock);
    } else {
        ts_reassign_event(sock, EV_WRITE, ts_response_method, sock);
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
        EV_READ, ts_request_method, sock);

    sock->ev = ev;
    event_add(ev, NULL);
}

static int ts_create_tcp_sock(struct ts_server_ctx *ctx) {
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
    struct ts_server_ctx ctx;

    ts_parse_server_opt(argc, argv, &ctx.config);
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
