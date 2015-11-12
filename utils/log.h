#ifndef TS_LOG_H
#define TS_LOG_H
#include <string.h>

#define TS_LOG_QUIET   -1
#define TS_LOG_ERROR    0
#define TS_LOG_WARNING  1
#define TS_LOG_INFO     2
#define TS_LOG_DEBUG    3

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

void ts_log(int level, const char *fmt, ...);
void ts_set_loglevel(int level);
int ts_get_loglevel();
int ts_enabled(int level);

#define _ts_log(level, fmt, ...) \
    ts_log(level, "%s:%d " fmt "\n", \
        __FILENAME__, __LINE__, ##__VA_ARGS__);

#define ts_log_e(fmt, ...) \
    do { \
        _ts_log(TS_LOG_ERROR, fmt, ##__VA_ARGS__) \
    } while (0)
#define ts_log_w(fmt, ...) \
    do { \
        _ts_log(TS_LOG_WARNING, fmt, ##__VA_ARGS__) \
    } while (0)
#define ts_log_i(fmt, ...) \
    do { \
        _ts_log(TS_LOG_INFO, fmt, ##__VA_ARGS__) \
    } while (0)
#define ts_log_d(fmt, ...) \
    do { \
        _ts_log(TS_LOG_DEBUG, fmt, ##__VA_ARGS__) \
    } while (0)

#endif

