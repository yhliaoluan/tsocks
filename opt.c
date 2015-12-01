#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "opt.h"
#include "log.h"
#include "utils.h"
#include "crypto.h"

static void local_usage() {
    printf("Usage:\n-p [port]\n-l [vdiweq]\n-s [remote_ipv4]\n-r [remote_port]\n"
        "-m [rc4]\n-k [password]\n");
}

static void server_usage() {
    printf("Usage:\n-p [port]\n-l [vdiweq]\n-m [rc4]\n-k [password]\n");
}

static void set_local_default(struct ts_local_opt *config) {
    config->port = 3333;
    config->log_level = TS_LOG_INFO;
    config->crypto_method = TS_CRYPTO_PLAIN;
    config->remote_port = 3125;
    config->remote_ipv4 = INADDR_LOOPBACK;
    config->key_size = 0;
}

static void set_server_default(struct ts_server_opt *config) {
    config->port = 3125;
    config->log_level = TS_LOG_INFO;
    config->crypto_method = TS_CRYPTO_PLAIN;
    config->key_size = 0;
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
    } else if (!strcmp(arg, "v")) {
        return TS_LOG_VERBOSE;
    }
    return TS_LOG_INFO;
}

static int ts_get_crypto_method(char *input) {
    if (strcmp("rc4", input) == 0) {
        return TS_CRYPTO_RC4;
    } else {
        return TS_CRYPTO_PLAIN;
    }
}

void ts_parse_local_opt(int argc, char **argv, struct ts_local_opt *config) {
    set_local_default(config);
    int c;
    while ((c = getopt(argc, argv, "p:l:s:r:m:k:h")) != -1) {
        switch (c) {
        case 'p':
            config->port = (uint16_t) atoi(optarg);
            break;
        case 'l':
            config->log_level = parse_log_level(optarg);
            break;
        case 's':
            config->remote_ipv4 = ntohl(inet_addr(optarg));
            break;
        case 'r':
            config->remote_port = (uint16_t) atoi(optarg);
            break;
        case 'm':
            config->crypto_method = ts_get_crypto_method(optarg);
            break;
        case 'k':
            config->key_size = min(strlen(optarg), 256);
            memcpy(config->key, optarg, config->key_size);
            break;
        case 'h':
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
    while ((c = getopt(argc, argv, "p:l:m:k:h")) != -1) {
        switch (c) {
        case 'p':
            config->port = (uint16_t) atoi(optarg);
            break;
        case 'l':
            config->log_level = parse_log_level(optarg);
            break;
        case 'm':
            config->crypto_method = ts_get_crypto_method(optarg);
            break;
        case 'k':
            config->key_size = min(strlen(optarg), 256);
            memcpy(config->key, optarg, config->key_size);
            break;
        case 'h':
        case '?':
        default:
            server_usage();
            exit(1);
        }
    }
}
