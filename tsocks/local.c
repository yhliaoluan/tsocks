#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "utils/log.h"
#include "utils/opt.h"

struct ts_local_ctx {
    int sockfd;
};

static int ts_start_local(struct ts_local_opt *config) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        ts_log_e("create socket failed");
        return -1;
    }
}

int main(int argc, char **argv) {

    struct ts_local_opt config = { 0 };

    if (ts_parse_local_opt(argc, argv, &config)) {
        exit(1);
    }

    if (ts_start_local(&config)) {
        exit(1);
    }
    
    exit(0);
}
