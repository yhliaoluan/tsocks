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

struct ts_session;

struct ts_sock_state {
    struct ts_sock *sock;
    struct event *ev;
    struct ts_session *session;
};

struct ts_session {
    struct ts_sock_state client;
    struct ts_sock_state remote;
}

void ts_session_close(struct ts_session *session) {
    if (session) {
        ts_close_sock(session.client.sock);
        event_free(session.client.ev);
        ts_close_sock(session.remote.sock);
        event_free(session.remote.ev);
        ts_free(session);
    }
}

struct ts_sock *ts_get_self(evutil_socket_t fd, struct ts_session *session) {
    return session->client.sock->fd == fd ? session->client.sock :
        session->remote.sock;
}

struct ts_sock *ts_get_peer(evutil_socket_t fd, struct ts_session *session) {
    return session->client.sock->fd == fd ? session->remote.sock :
        session->client.sock;
}

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

int ts_reassign_ev(struct ts_sock_state *state, evutil_socket_t fd, short what,
    void (*cb) (evutil_socket_t, short, void *)) {

    struct event *ev = event_new(event_get_base(state->ev), fd, what,
        cb, state);
    if (!ev) return -1;
    event_free(state->ev);
    state->ev = ev;
    return event_add(ev, NULL);
}

void ts_relay_read(evutil_socket_t fd, short what, void *arg);
void ts_relay_write(evutil_socket_t fd, short what, void *arg) {

    struct ts_sock_state *state = arg;
    struct ts_sock *sock = ts_get_self(fd, state->session);

    ts_assert_true(fd == sock->fd);
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
        if (ts_reassign_ev(state, EV_READ, ts_relay_read) < 0) {
            goto failed;
        }
    } else {
        if (ts_reassign_ev(state, EV_WRITE, ts_relay_write) < 0) {
            goto failed;
        }
    }

    return;

failed:
    ts_session_close(state->session);
}

void ts_relay_read(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock_state *state = arg;
    struct ts_sock *sock = state->sock;
    struct ts_sock *peer = sock->peer;

    ts_assert_true(fd == sock->fd);
    if (ts_sock_recv2peer(sock) <= 0) {
        goto failed;
    }

    ts_log_d("receive %u bytes from %d", peer->output->size, sock->fd);
    ts_print_bin_as_hex(peer->output->buf.buffer, peer->output->size);
    state->sock = peer;
    if (ts_reassign_ev(state, EV_WRITE, ts_relay_write) < 0) {
        goto failed;
    }
    return;

failed:
    ts_close_sock(sock);
    peer->peer = NULL;
    event_free(state->ev);
    ts_free(state);
}

void ts_response_conn(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock_state *state = arg;
    struct ts_sock *sock = state->sock;
    struct ts_sock *peer = sock->peer;
    struct ts_sock_state *peer_state = NULL;

    ts_assert_true(fd == sock->fd);
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

    struct event_base *base = event_get_base(state->ev);
    if (ts_reassign_ev(state, EV_READ, ts_relay_read) < 0) {
        goto failed;
    }

    peer_state = ts_malloc(sizeof(struct ts_sock_state));
    peer_state->sock = peer;
    peer_state->ev = event_new(base, peer->fd, EV_READ, ts_relay_read, peer_state);
    if (event_add(peer_state->ev, NULL) < 0) {
        goto failed;
    }

    return;

failed:
    ts_close_sock(sock);
    ts_close_sock(peer);
    event_free(state->ev);
    ts_free(state);
    if (peer_state) {
        event_free(peer_state->ev);
        ts_free(peer_state);
    }
}

void ts_peer_conn_ready(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock_state *state = arg;
    struct ts_sock *sock = state->sock;
    struct ts_sock *peer = sock->peer;

    ts_assert_true(fd == sock->fd);
    state->sock = peer;
    if (ts_reassign_ev(state, EV_WRITE, ts_response_conn) < 0) {
        ts_close_sock(sock);
        ts_close_sock(peer);
        event_free(state->ev);
        ts_free(state);
    }
}

void ts_request_conn(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock_state *state = arg;
    struct ts_sock *sock = state->sock;
    ts_assert_true(fd == sock->fd);
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
            state->sock = peer;
            if (ts_reassign_ev(state, EV_WRITE, ts_peer_conn_ready) < 0) {
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
    event_free(state->ev);
    ts_free(state);
}

void ts_response_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock_state *state = arg;
    struct ts_sock *sock = state->sock;
    ts_assert_true(fd == sock->fd);
    if (send(sock->fd, "\5\0", 2, 0) != 2) {
        ts_sock_state_free(state);
    } else {
        if (ts_reassign_ev(state, EV_READ, ts_request_conn) < 0) {
            ts_sock_state_free(state);
        }
    }
}

void ts_request_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_sock_state *state = arg;
    struct ts_sock *sock = state->sock;
    ts_assert_true(fd == sock->fd);
    unsigned char buf[512];
    int size = recv(sock->fd, buf, sizeof(buf), 0);
    if (size < 0 || buf[0] != 5) {
        ts_sock_state_free(state);
    } else {
        ts_print_bin_as_hex(buf, size);
        if (ts_reassign_ev(state, EV_WRITE, ts_response_method) < 0) {
            ts_sock_state_free(state);
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

    struct ts_session *session = ts_malloc(sizeof(struct ts_session));
    memset(session, 0, sizeof(struct ts_session));
    struct ts_sock_state *state = &session->ltor;
    state->sock = ts_sock_new(client);
    state->ev = event_new((struct event_base *)arg, client, EV_READ, ts_request_method, state);
    state->session = session;
    if (event_add(state->ev, NULL) < 0) {
        ts_sock_state_free(state);
    }
}

int main(int argc, char **argv) {
    struct ts_server_ctx ctx;

    ts_parse_server_opt(argc, argv, &ctx.config);
    ts_set_log_level(ctx.config.log_level);

    ts_log_i("use config: log_level:%s port:%u",
        ts_level2str(ctx.config.log_level), ctx.config.port);
    int fd = ts_create_tcp_sock(ctx.config.port);
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
