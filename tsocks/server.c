#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/util.h>
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
    struct event_base *base;
};

static void ts_relay_rtoc_read(evutil_socket_t fd, short what, void *arg);
static void ts_relay_rtoc_write(evutil_socket_t fd, short what, void *arg) {

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

static void ts_relay_rtoc_read(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->remote->fd);
    assert(what == EV_READ);

    if (ts_recv2stream(session->remote->fd, session->client->output) <= 0) {
        goto failed;
    }
    ts_stream_encrypt(session->client->output, session->crypto);

    ts_log_d("receive %u bytes from %d", session->client->output->size,
        session->remote->fd);
    ts_stream_print(session->client->output);
    session->rtoc = ts_reassign_ev(session->rtoc, session->client->fd, EV_WRITE,
        ts_relay_rtoc_write, session);
    assert(session->rtoc);
    return;

failed:
    ts_session_close(session);
}


static void ts_relay_ctor_read(evutil_socket_t fd, short what, void *arg);
static void ts_relay_ctor_write(evutil_socket_t fd, short what, void *arg) {

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

static void ts_relay_ctor_read(evutil_socket_t fd, short what, void *arg) {

    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_READ);

    if (ts_recv2stream(session->client->fd, session->remote->output) <= 0) {
        goto failed;
    }
    ts_stream_decrypt(session->remote->output, session->crypto);

    ts_log_d("receive %u bytes from %d", session->remote->output->size,
        session->client->fd);
    ts_stream_print(session->remote->output);
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

    ts_crypto_encrypt(session->crypto, res, res, sizeof(res));
    if (send(session->client->fd, res, sizeof(res), 0) != 10) {
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

static void ts_conn_sockaddr(struct sockaddr *addr, size_t size, struct ts_session *session) {

    session->remote = ts_conn(addr, size);

    if (session->remote) {
        ts_log_d("client %d to remote %d", session->client->fd,
            session->remote->fd);
        session->ctor = ts_reassign_ev(session->ctor, session->remote->fd, EV_WRITE,
            ts_remote_conn_ready, session);
        assert(session->ctor);
    } else {
        ts_log_e("create peer failed");
        ts_session_close(session);
    }
}

static void ts_conn_host(const char *hostname, struct ts_session *session) {


}

static void ts_conn_ipv4(unsigned long ip, unsigned short port,
    struct ts_session *session) {

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ip);
    addr.sin_port = htons(port);

    ts_conn_sockaddr((struct sockaddr *)&addr, sizeof(addr), session);
}

void ts_request_conn(evutil_socket_t fd, short what, void *arg) {
    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_READ);

    struct ts_sock *client = session->client;
    ssize_t size = ts_recv2stream(client->fd, client->input);
    if (size <= 0) {
        goto failed;
    }
    ts_stream_decrypt(client->input, session->crypto);
    unsigned char *buf = client->input->buf.buffer;
    char host[256] = { 0 };
    if (size < 10) {
        goto failed;
    }
    if (buf[1] != 1) {
        ts_log_w("only support CONNECT cmd.");
        goto failed;
    }
    if (buf[2] != 0) {
        ts_log_w("reserved field must be 0.");
        goto failed;
    }
    ts_stream_print(client->input);
    if (buf[3] == 3) {
        memcpy(host, &buf[5], buf[4]);
        ts_conn_host(host, session);
    } else if (buf[3] == 1) {
        // ipv4
        ts_conn_ipv4(ntohl(*(unsigned long *)&buf[4]),
            ntohs(*(unsigned short *)&buf[8]), session);
    } else {
        ts_log_w("ipv6 currently not support");
    }

    return;

failed:
    ts_session_close(session);
}

void ts_response_method(evutil_socket_t fd, short what, void *arg) {
    struct ts_session *session = arg;
    assert(fd == session->client->fd);
    assert(what == EV_WRITE);
    unsigned char buf[2] = { 5, 0 };
    ts_crypto_encrypt(session->crypto, buf, buf, sizeof(buf));
    if (send(session->client->fd, buf, sizeof(buf), 0) != 2) {
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

    struct ts_sock *client = session->client;
    int size = ts_recv2stream(client->fd, client->input);
    if (size <= 0) goto failed;

    ts_stream_decrypt(client->input, session->crypto);
    ts_stream_print(client->input);
    unsigned char *buf = client->input->buf.buffer;
    if (buf[0] != 5) {
        ts_log_w("only support socks v5");
        goto failed;
    }

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

    struct ts_server_ctx *ctx = arg;
    struct ts_session *session = ts_malloc(sizeof(struct ts_session));
    memset(session, 0, sizeof(struct ts_session));
    session->client = ts_sock_new(client);
    session->ctor = event_new(ctx->base, client,
        EV_READ, ts_request_method, session);
    session->crypto = ts_crypto_new(ctx->config.crypto_method, ctx->config.key,
        ctx->config.key_size);

    if (event_add(session->ctor, NULL) < 0) {
        ts_session_close(session);
    }
}

void ts_sigint(evutil_socket_t fd, short what, void *arg) {
    event_base_loopbreak((struct event_base *) arg);
}

int main(int argc, char **argv) {
    struct ts_server_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ts_parse_server_opt(argc, argv, &ctx.config);
    ts_set_log_level(ctx.config.log_level);

    int fd = ts_create_tcp_sock(ctx.config.port);
    struct event_base *base = event_base_new();
    if (!base) {
        sys_err("create event_base failed.");
    }

    ctx.base = base;

    struct event *ev = event_new(base, fd, EV_READ | EV_PERSIST, ts_tcp_accept, &ctx);
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

