#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "utils/opt.h"
#include "utils/log.h"

static void local_usage() {
    ts_log_i("\nUsage:\n-p [port]\n-l [diweq]");
}

static void server_usage() {
    ts_log_i("\nUsage:\n-p [port]\n-l [diweq]");
}

static void set_local_default(struct ts_local_opt *config) {
    config->port = 3125;
    config->log_level = TS_LOG_INFO;
}

static void set_server_default(struct ts_server_opt *config) {
    config->port = 3125;
    config->log_level = TS_LOG_INFO;
}

static int parse_log_level(const char *arg) {
    if (!strcmp(arg, "d")) {
        return TS_LOG_DEBUG;
    } else if (!strcmp(arg, "w")) {
        return TS_LOG_WARNING;
    } else if (!strcmp(arg, "e")) {
        return TS_LOG_ERROR;
    } else if (!strcmp(arg, "q")) {
        return TS_LOG_QUIET;
    }
    return TS_LOG_INFO;
}

void ts_parse_local_opt(int argc, char **argv, struct ts_local_opt *config) {
    set_local_default(config);
    int c;
    while ((c = getopt(argc, argv, "p:l:")) != -1) {
        switch (c) {
        case 'p':
            config->port = (uint16_t) atoi(optarg);
            break;
        case 'l':
            config->log_level = parse_log_level(optarg);
            break;
        case '?':
        default:
            local_usage();
            exit(1);
        }
    }
}

void ts_parse_server_opt(int argc, char **argv, struct ts_server_opt *config) {
    set_server_default(config);
    int c;
    while ((c = getopt(argc, argv, "p:l:")) != -1) {
        switch (c) {
        case 'p':
            config->port = (uint16_t) atoi(optarg);
            break;
        case 'l':
            config->log_level = parse_log_level(optarg);
            break;
        case '?':
        default:
            server_usage();
            exit(1);
        }
    }
}
