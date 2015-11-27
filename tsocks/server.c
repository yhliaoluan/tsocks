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
#include <signal.h>
#include "log.h"
#include "opt.h"
#include "debug.h"
#include "memory.h"
#include "utils.h"
#include "socks.h"

struct ts_server_ctx {
    struct ts_server_opt config;
};

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
    if (size <= 0) goto failed;

    ts_print_bin_as_hex(buf, size);
    if (buf[0] != 5) goto failed;

    session->rtoc = event_new(event_get_base(session->ctor), session->client->fd,
        EV_WRITE, ts_response_method, session);
    if (event_add(session->rtoc, NULL) < 0) {
        ts_session_close(session);
    }
    return;
failed:
    ts_session_close(session);
}

void ts_tcp_accept(evutil_socket_t fd, short what, void *arg) {
    struct sockaddr_in addr;
    socklen_t size = sizeof(addr);
    int client = accept(fd, (struct sockaddr *) &addr, &size);

    if (client < 0) {
        sys_err("accept error. %s (%d) size:%u", strerror(errno), errno, size);
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

void ts_sigint(evutil_socket_t fd, short what, void *arg) {
    event_base_loopbreak((struct event_base *) arg);
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

    struct event *evsigint = evsignal_new(base, SIGINT, ts_sigint, base);
    if (event_add(evsigint, NULL) < 0) {
        sys_err("add signal event failed");
    }
    
    event_base_dispatch(base);
    event_free(ev);
    event_base_free(base);

    size_t mem = ts_mem_size();
    ts_log_i("memory: %u bytes", mem);

    exit(0);
}

