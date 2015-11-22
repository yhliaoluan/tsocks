#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>

#define CHECK(x) \
    do { \
        if ((x) < 0) { \
            printf("error %s:%d\n", __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

int main(int argc, char **argv) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(3125);
    inet_aton("127.0.0.1", &addr.sin_addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd);
    CHECK(connect(fd, (struct sockaddr *) &addr, sizeof(addr)));
    unsigned char buf[1024];
    for (;;) {
        printf("send: ");
        int val;
        int i = 0;
        while (scanf("%x", &val) != EOF) {
            buf[i++] = val;
        }
        CHECK(send(fd, buf, i, 0));
        i = recv(fd, buf, sizeof(buf), 0);
        if (i <= 0) {
            break;
        }
        printf("recv: ");
        CHECK(i);
        unsigned char *ptr = buf;
        while (i-- > 0) {
            printf("%02X ", *ptr++);
        }
        printf("...\n");
    }
    shutdown(fd, 2);
    return 0;
}
