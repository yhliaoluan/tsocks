#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "log.h"

const char *ts_level2str(int level) {
    switch (level) {
    case TS_LOG_ERROR:
        return "error";
    case TS_LOG_WARNING:
        return "warn";
    case TS_LOG_INFO:
        return "info";
    case TS_LOG_DEBUG:
        return "debug";
    case TS_LOG_VERBOSE:
        return "verbose";
    default:
        return "unknown";
    }
}

static int g_level;

void ts_log(int level, const char *fmt, ...) {
    if (level > g_level) return;
    va_list va;
    va_start(va, fmt);
    time_t curtime = time(NULL);
    struct tm *tm = localtime(&curtime);
    printf("%02d:%02d:%02d [%s] ", tm->tm_hour, tm->tm_min,
        tm->tm_sec, ts_level2str(level));
    vprintf(fmt, va);
    va_end(va);
}

void ts_set_log_level(int level) {
    g_level = level;
}

int ts_get_log_level() {
    return g_level;
}

int ts_enabled(int level) {
    return g_level >= level;
}
