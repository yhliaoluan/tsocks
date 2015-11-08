#include <unistd.h>
#include <stdlib.h>
#include "utils/opt.h"
#include "utils/log.h"

static void usage() {
    ts_log_i("\nUsage:\n-p [port]\n");
}

void ts_parse_local_opt(int argc, char **argv, struct ts_local_opt *config) {
    int c;
    while ((c = getopt(argc, argv, "p:")) != -1) {
        switch (c) {
        case 'p':
            config->port = (uint16_t) atoi(optarg);
            break;
        case '?':
        default:
            usage();
            exit(1);
        }
    }
    if (!config->port) {
        usage();
        exit(1);
    }
    ts_log_d("parse configuration completed. port:%u", config->port);
}
