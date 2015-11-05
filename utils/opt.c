#include <unistd.h>
#include "opt.h"
#include "log.h"

static void usage() {
    ts_log_i("\nUsage:\n-p [port]\n");
}

int ts_parse_local_opt(int argc, char **argv, struct ts_local_opt *config) {
    int c;
    while ((c = getopt(argc, argv, "p:")) != -1) {
        switch (c) {
        case 'p':
            config->port = (uint16_t) atoi(optarg);
            break;
        case '?':
        default:
            usage();
            return -1;
        }
    }
    return 0;
}
