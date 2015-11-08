#ifndef _TS_DEBUG_H_
#define _TS_DEBUG_H_
#include "utils/log.h"

#define sys_err(fmt, ...) \
    do { \
        ts_log_e(fmt, ##__VA_ARGS__); \
        exit(1); \
    } while (0)

#endif
