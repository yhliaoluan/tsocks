#ifndef TS_LOG_H
#define TS_LOG_H

#define TS_LOG_QUIET   -1
#define TS_LOG_ERROR    0
#define TS_LOG_WARNING  1
#define TS_LOG_INFO     2
#define TS_LOG_DEBUG    3

void ts_log(int level, const char *fmt, ...);

#define _ts_log(level, fmt, ...) \
    ts_log(level, "%s:%d:%s(): " fmt "\n", \
        __FILE__, __LINE__, __func__, ##__VA_ARGS__);

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
