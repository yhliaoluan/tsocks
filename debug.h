#ifndef _TS_DEBUG_H_
#define _TS_DEBUG_H_
#include "ts_config.h"
#include "log.h"

#define sys_err(fmt, ...) \
    do { \
        ts_log_e(fmt, ##__VA_ARGS__); \
        exit(1); \
    } while (0)

#ifdef DEBUG
#define ts_assert_true(r) \
    do { \
        printf("TEST %s:%d ", __FILENAME__, __LINE__); \
        if (!(r)) { \
            printf("FAILED!\n"); \
            exit(1); \
        } \
        printf("PASSED!\n"); \
    } while (0)
#else
#define ts_assert_true(r)
#endif

static void ts_print_bin_as_hex(unsigned char *buf, size_t size) {
    if (ts_enabled(TS_LOG_DEBUG)) {
        char msg[512];
        char *ptr = msg;
        size_t i = 0;
        while (i < size && i < 100) {
            sprintf(ptr, "0x%02X ", *buf++);
            ptr += 5;
            i++;
        }
        sprintf(ptr, "...");
        ts_log_d("%s", msg);
    }
}

#endif
