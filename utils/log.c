#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "log.h"

static const char *level_to_str(int level) {
    switch (level) {
    case TS_LOG_ERROR:
        return "error";
    case TS_LOG_WARNING:
        return "warning";
    case TS_LOG_INFO:
        return "info";
    case TS_LOG_DEBUG:
        return "debug";
    default:
        return "unknown";
    }
}

void ts_log(int level, const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    time_t curtime = time(NULL);
    struct tm *tm = localtime(&curtime);
    printf("%02d:%02d:%02d [%s] ", tm->tm_hour, tm->tm_min,
        tm->tm_sec, level_to_str(level));
    vprintf(fmt, va);
    va_end(va);
}

