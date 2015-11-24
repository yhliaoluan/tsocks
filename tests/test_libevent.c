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

static void ts_read(evutil_socket_t fd, short what, void *arg) {
    printf("%d can read\n", fd);
    char buf[32] = {0};
    ssize_t size = recv(fd, buf, sizeof(buf), 0);
    printf("%s", buf);
}

static void ts_write(evutil_socket_t fd, short what, void *arg) {
    printf("%d can write\n", fd);
    send(fd, "from server", 11, 0);
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

    struct event_base *base = arg;
    event_add(event_new(base, client, EV_READ, ts_read, base), NULL);
    event_add(event_new(base, client, EV_WRITE, ts_write, base), NULL);
}

int main(int argc, char **argv) {
    printf("enter\n");
    int fd = ts_create_tcp_sock(5555);
    struct event_base *base = event_base_new();
    if (!base) {
        sys_err("create event_base failed.");
    }

    struct event *ev = event_new(base, fd, EV_READ | EV_PERSIST, ts_tcp_accept, base);
    if (event_add(ev, NULL) < 0) {
        sys_err("add event failed");
    }
    
    printf("listening...\n");
    event_base_dispatch(base);
    return 0;
}
