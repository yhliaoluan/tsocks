#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <string.h>
#include <errno.h>
#include "log.h"
#include "opt.h"
#include "debug.h"
#include "memory.h"
#include "utils.h"
#include "socks.h"

struct ts_server_ctx {
    struct ts_server_opt config;
};

struct ts_sock *ts_conn_ipv4(unsigned long ip, unsigned short port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ts_log_e("socket failed");
        goto failed;
    }

    if (ts_socket_nonblock(fd) < 0) {
        ts_log_e("fd %d set nonblock failed", fd);
        goto failed;
    }

    struct sockaddr_in remote;
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = ip;
    remote.sin_port = port;

    //do not check the result, if it failed, the following recv call will failed too
    ts_log_d("connect to %s:%u...", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
    if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0 &&
        errno != EINPROGRESS) {

        ts_log_e("connect failed, errno:%d", errno);
        goto failed;
    }

    return ts_sock_new(fd);

failed:
    if (fd > 0) shutdown(fd, 2);
    return NULL;
}

struct event *ts_assign_event(struct ts_sock *sock, struct event_base *base, short what,
    void (*cb) (evutil_socket_t, short, void *), void *arg) {

    struct event *ev = event_new(base, sock->fd, what, cb, arg);
    if (!ev) return NULL;
    if (sock->ev) {
        event_free(sock->ev);
    }
    sock->ev = ev;
    event_add(ev, NULL);
    return ev;
}

void ts_relay_read(evutil_socket_t fd, short what, void *arg);
void ts_relay_write(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    struct ts_sock *peer = sock->peer;

    ssize_t sent = send(sock->fd, sock->output->buf.buffer + sock->output->pos,
        sock->output->size - sock->output->pos, 0);
    if (sent <= 0) {
        goto failed;
    }
    sock->output->pos += sent;
    ts_assert_true(sock->output->pos <= sock->output->size);
    ts_log_d("after sending to %d, size:%u, pos:%u", sock->fd,
        sock->output->size, sock->output->pos);
    if (sock->output->pos == sock->output->size) {
        if (!ts_assign_event(peer, event_get_base(peer->ev), EV_READ,
                ts_relay_read, peer)) {
            goto failed;
        }
    } else {
        if (!ts_assign_event(sock, event_get_base(sock->ev), EV_WRITE,
                ts_relay_write, sock)) {
            goto failed;
        }
    }

    return;

failed:
    ts_close_sock(sock);
    ts_close_sock(peer);
}

void ts_relay_read(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    struct ts_sock *peer = sock->peer;

    if (ts_sock_recv2peer(sock) <= 0) {
        goto failed;
    }

    ts_log_d("receive %u bytes from %d", peer->output->size, sock->fd);
    ts_print_bin_as_hex(peer->output->buf.buffer, peer->output->size);
    if (!ts_assign_event(peer, event_get_base(peer->ev), EV_WRITE,
            ts_relay_write, peer)) {
        goto failed;
    }
    return;

failed:
    ts_close_sock(sock);
    ts_close_sock(peer);
}

void ts_response_conn(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    struct ts_sock *peer = sock->peer;

    struct sockaddr_in addr;
    socklen_t len = sizeof(struct sockaddr_in);
    if (getsockname(peer->fd, (struct sockaddr *)&addr, &len) < 0) {
        ts_log_e("getsockname failed");
        goto failed;
    }

    unsigned char res[10] = { 5, 0, 0, 1 };
    memcpy(&res[4], &addr.sin_addr.s_addr, 4);
    memcpy(&res[8], &addr.sin_port, 2);

    if (send(sock->fd, res, 10, 0) != 10) {
        goto failed;
    }

    struct event_base *base = event_get_base(sock->ev);
    if (!ts_assign_event(sock, base, EV_READ, ts_relay_read, sock) ||
        !ts_assign_event(peer, base, EV_READ, ts_relay_read, peer)) {
        goto failed;
    }

    return;
failed:
    ts_close_sock(sock);
    ts_close_sock(peer);
}

void ts_peer_conn_ready(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *peer = arg;
    struct ts_sock *sock = peer->peer;

    if (!ts_assign_event(sock, event_get_base(sock->ev), EV_WRITE,
        ts_response_conn, sock)) {

        ts_close_sock(sock);
        ts_close_sock(peer);
    }
}

void ts_request_conn(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    struct ts_sock *peer = NULL;
    unsigned char buf[512];
    int size = recv(fd, buf, sizeof(buf), 0);
    if (size < 10 || buf[1] != 1 || buf[2] != 0) {
        goto failed;
    } else {
        ts_print_bin_as_hex(buf, size);
        if (buf[3] == 1) {
            // ipv4
            peer = ts_conn_ipv4(*(unsigned long *)&buf[4], *(unsigned short *)&buf[8]);
        } else if (buf[3] == 3) {
            ts_log_d("hostname currently not support");
        } else {
            ts_log_d("ipv6 currently not support");
        }
        if (peer) {
            sock->peer = peer;
            peer->peer = sock;
            ts_log_d("set up peer %d -- %d", sock->fd, peer->fd);
            if (!ts_assign_event(peer, event_get_base(sock->ev), EV_WRITE,
                    ts_peer_conn_ready, peer)) {
                goto failed;
            }
        } else {
            ts_log_e("create peer failed");
            goto failed;
        }
    }

    return;

failed:
    ts_close_sock(sock);
    ts_close_sock(peer);
}

void ts_response_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    if (send(fd, "\5\0", 2, 0) != 2) {
        ts_close_sock(sock);
    } else {
        if (!ts_assign_event(sock, event_get_base(sock->ev),
                EV_READ, ts_request_conn, sock)) {
            ts_close_sock(sock);
        }
    }
}

void ts_request_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock *sock = arg;
    unsigned char buf[512];
    int size = recv(fd, buf, sizeof(buf), 0);
    if (size < 0 || buf[0] != 5) {
        ts_close_sock(sock);
    } else {
        ts_print_bin_as_hex(buf, size);
        if (!ts_assign_event(sock, event_get_base(sock->ev), EV_WRITE,
            ts_response_method, sock)) {
            ts_close_sock(sock);
        }
    }
}

static void ts_tcp_accept(evutil_socket_t fd, short what, void *arg) {
    struct sockaddr_in addr;
    socklen_t size = sizeof(addr);
    int client = accept(fd, (struct sockaddr *) &addr, &size);

    if (client < 0) {
        sys_err("accept error.");
    }

    if (ts_socket_nonblock(client) < 0) {
        sys_err("fcntl error.");
    }

    ts_log_d("accept client %d from %s:%u", client,
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    struct ts_sock *sock = ts_sock_new(client);
    if (!ts_assign_event(sock, (struct event_base *)arg, EV_READ,
            ts_request_method, sock)) {
        ts_close_sock(sock);
    }
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

    if (ts_socket_nonblock(fd) < 0) {
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
