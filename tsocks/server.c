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
#include <assert.h>
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

struct event *ts_reassign_ev(struct event *ev, evutil_socket_t fd, short what,
    void (*cb) (evutil_socket_t, short, void *), void *args) {

    struct event *new_ev = event_new(event_get_base(ev), fd, what, cb, args);
    if (!new_ev) return NULL;
    event_free(ev);
    if (event_add(new_ev, NULL) < 0) return NULL;
    return new_ev;
}

ssize_t ts_flush_once(struct ts_sock *sock) {
    ssize_t sent = send(sock->fd, sock->output->buf.buffer + sock->output->pos,
        sock->output->size - sock->output->pos, 0);
    if (sent > 0) {
        sock->output->pos += sent;
        assert(sock->output->pos <= sock->output->size);
        ts_log_d("after sending to %d, size:%u, pos:%u", sock->fd,
            sock->output->size, sock->output->pos);
    }
    return sent;
}

void ts_relay_rtoc_read(evutil_socket_t fd, short what, void *arg);
void ts_relay_rtoc_write(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_WRITE);

    if (ts_flush_once(session->client) <= 0) {
        ts_log_d("flush to %d failed", session->client->fd);
        goto failed;
    }

    if (session->client->output->pos == session->client->output->size) {
        session->rtoc = ts_reassign_ev(session->rtoc, session->remote->fd, EV_READ,
            ts_relay_rtoc_read, session);
        assert(session->rtoc);
    } else {
        session->rtoc = ts_reassign_ev(session->rtoc, session->client->fd, EV_WRITE,
            ts_relay_rtoc_write, session);
        assert(session->rtoc);
    }

    return;

failed:
    ts_session_close(session);
}

void ts_relay_rtoc_read(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->remote->fd);
    assert(what == EV_READ);

    if (ts_sock_recv2peer(session->remote, session->client) <= 0) {
        goto failed;
    }

    ts_log_d("receive %u bytes from %d", session->client->output->size,
        session->remote->fd);
    ts_print_bin_as_hex(session->client->output->buf.buffer, session->client->output->size);
    session->rtoc = ts_reassign_ev(session->rtoc, session->client->fd, EV_WRITE,
        ts_relay_rtoc_write, session);
    assert(session->rtoc);
    return;

failed:
    ts_session_close(session);
}


void ts_relay_ctor_read(evutil_socket_t fd, short what, void *arg);
void ts_relay_ctor_write(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->remote->fd);
    assert(what == EV_WRITE);

    if (ts_flush_once(session->remote) <= 0) {
        ts_log_d("flush to %d failed", session->remote->fd);
        goto failed;
    }

    if (session->remote->output->pos == session->remote->output->size) {
        session->ctor = ts_reassign_ev(session->ctor, session->client->fd, EV_READ,
            ts_relay_ctor_read, session);
        assert(session->ctor);
    } else {
        session->ctor = ts_reassign_ev(session->ctor, session->remote->fd, EV_WRITE,
            ts_relay_ctor_write, session);
        assert(session->ctor);
    }

    return;

failed:
    ts_session_close(session);
}

void ts_relay_ctor_read(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_READ);

    if (ts_sock_recv2peer(session->client, session->remote) <= 0) {
        goto failed;
    }

    ts_log_d("receive %u bytes from %d", session->remote->output->size,
        session->client->fd);
    ts_print_bin_as_hex(session->remote->output->buf.buffer, session->remote->output->size);
    session->ctor = ts_reassign_ev(session->ctor, session->remote->fd, EV_WRITE,
        ts_relay_ctor_write, session);
    assert(session->ctor);
    return;

failed:
    ts_session_close(session);
}

void ts_response_conn(evutil_socket_t fd, short what, void *arg) {
    struct ts_session *session = arg;

    assert(fd == session->client->fd);
    assert(what == EV_WRITE);

    struct sockaddr_in addr;
    socklen_t len = sizeof(struct sockaddr_in);
    if (getsockname(session->remote->fd, (struct sockaddr *)&addr, &len) < 0) {
        ts_log_e("getsockname failed");
        goto failed;
    }

    unsigned char res[10] = { 5, 0, 0, 1 };
    memcpy(&res[4], &addr.sin_addr.s_addr, 4);
    memcpy(&res[8], &addr.sin_port, 2);

    if (send(session->client->fd, res, 10, 0) != 10) {
        goto failed;
    }

    session->rtoc = ts_reassign_ev(session->rtoc, session->remote->fd, EV_READ,
        ts_relay_rtoc_read, session);
    assert(session->rtoc);

    session->ctor = ts_reassign_ev(session->ctor, session->client->fd, EV_READ,
        ts_relay_ctor_read, session);
    assert(session->ctor);

    return;

failed:
    ts_session_close(session);
}

void ts_remote_conn_ready(evutil_socket_t fd, short what, void *arg) {
    struct ts_session *session = arg;

    assert(fd == session->remote->fd);
    assert(what == EV_WRITE);

    session->rtoc = ts_reassign_ev(session->rtoc, session->client->fd, EV_WRITE,
        ts_response_conn, session);
    assert(session->rtoc);
}

void ts_request_conn(evutil_socket_t fd, short what, void *arg) {
    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_READ);
    unsigned char buf[512];
    int size = recv(session->client->fd, buf, sizeof(buf), 0);
    if (size < 10 || buf[1] != 1 || buf[2] != 0) {
        goto failed;
    } else {
        ts_print_bin_as_hex(buf, size);
        if (buf[3] == 1) {
            // ipv4
            session->remote = ts_conn_ipv4(*(unsigned long *)&buf[4], *(unsigned short *)&buf[8]);
        } else if (buf[3] == 3) {
            ts_log_d("hostname currently not support");
        } else {
            ts_log_d("ipv6 currently not support");
        }
        if (session->remote) {
            ts_log_d("client %d to remote %d", session->client->fd,
                session->remote->fd);
            session->ctor = ts_reassign_ev(session->ctor, session->remote->fd, EV_WRITE,
                ts_remote_conn_ready, session);
            assert(session->ctor);
        } else {
            ts_log_e("create peer failed");
            goto failed;
        }
    }

    return;

failed:
    ts_session_close(session);
}

void ts_response_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_WRITE);
    if (send(session->client->fd, "\5\0", 2, 0) != 2) {
        ts_session_close(session);
    } else {
        session->ctor = ts_reassign_ev(session->ctor, session->client->fd, EV_READ,
            ts_request_conn, session);
        assert(session->ctor);
    }
}

void ts_request_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_READ);

    unsigned char buf[512];
    int size = recv(session->client->fd, buf, sizeof(buf), 0);
    if (size < 0 || buf[0] != 5) {
        ts_session_close(session);
    } else {
        ts_print_bin_as_hex(buf, size);
        session->rtoc = event_new(event_get_base(session->ctor), session->client->fd,
            EV_WRITE, ts_response_method, session);
        if (event_add(session->rtoc, NULL) < 0) {
            ts_session_close(session);
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
    session->client = ts_sock_new(client);
    session->ctor = event_new((struct event_base *)arg, client,
        EV_READ, ts_request_method, session);
    if (event_add(session->ctor, NULL) < 0) {
        ts_session_close(session);
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

