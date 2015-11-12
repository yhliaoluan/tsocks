#ifndef _TS_DEBUG_H_
#define _TS_DEBUG_H_
#include "utils/log.h"

#define sys_err(fmt, ...) \
    do { \
        ts_log_e(fmt, ##__VA_ARGS__); \
        exit(1); \
    } while (0)

static void print_bin_as_hex(unsigned char *buf, size_t size) {
    if (ts_enabled(TS_LOG_DEBUG)) {
        size_t i = 0;
        while (i++ < size) {
            ts_log_d("0x%02X ", *buf++);
        }
    }
}

#endif
