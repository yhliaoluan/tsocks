#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "utils/opt.h"
#include "utils/log.h"

static void usage() {
    ts_log_i("\nUsage:\n-p [port]\n-l [diweq]");
}

static void set_default(struct ts_local_opt *config) {
    config->port = 3125;
    config->loglevel = TS_LOG_INFO;
}

void ts_parse_local_opt(int argc, char **argv, struct ts_local_opt *config) {
    set_default(config);
    int c;
    while ((c = getopt(argc, argv, "p:l:")) != -1) {
        switch (c) {
        case 'p':
            config->port = (uint16_t) atoi(optarg);
            break;
        case 'l':
            if (!strcmp(optarg, "d")) {
                config->loglevel = TS_LOG_DEBUG;
            } else if (!strcmp(optarg, "i")) {
                config->loglevel = TS_LOG_INFO;
            } else if (!strcmp(optarg, "w")) {
                config->loglevel = TS_LOG_WARNING;
            } else if (!strcmp(optarg, "e")) {
                config->loglevel = TS_LOG_ERROR;
            } else if (!strcmp(optarg, "q")) {
                config->loglevel = TS_LOG_QUIET;
            }
            break;
        case '?':
        default:
            usage();
            exit(1);
        }
    }
}
