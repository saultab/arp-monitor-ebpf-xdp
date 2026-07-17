/* SPDX-License-Identifier: MIT */
#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <syslog.h>

enum log_level {
    LOG_LVL_DEBUG = 0,
    LOG_LVL_INFO  = 1,
    LOG_LVL_WARN  = 2,
    LOG_LVL_ERR   = 3,
};

static enum log_level g_log_level = LOG_LVL_INFO;
static FILE *g_log_file = NULL;
static int g_use_syslog = 0;

static const char *log_level_str[] = {
    "DEBUG", "INFO", "WARN", "ERROR"
};

static const int log_level_syslog[] = {
    LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERR
};

static inline void log_init(enum log_level level, FILE *file, int use_syslog)
{
    g_log_level = level;
    g_log_file = file ? file : stderr;
    g_use_syslog = use_syslog;
    if (use_syslog)
        openlog("arp-monitor", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

static inline void log_cleanup(void)
{
    if (g_use_syslog)
        closelog();
    if (g_log_file && g_log_file != stderr && g_log_file != stdout)
        fclose(g_log_file);
}

__attribute__((format(printf, 4, 5)))
static inline void log_msg(enum log_level level, const char *file,
                           int line, const char *fmt, ...)
{
    if (level < g_log_level)
        return;

    va_list ap;
    va_start(ap, fmt);

    if (g_use_syslog) {
        vsyslog(log_level_syslog[level], fmt, ap);
        va_end(ap);
        return;
    }

    /* Timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", &tm);

    fprintf(g_log_file, "%s.%03ld [%-5s] ",
            timebuf, ts.tv_nsec / 1000000, log_level_str[level]);

    if (level == LOG_LVL_DEBUG)
        fprintf(g_log_file, "%s:%d ", file, line);

    vfprintf(g_log_file, fmt, ap);
    fprintf(g_log_file, "\n");
    fflush(g_log_file);

    va_end(ap);
}

/* Avoid conflicts with syslog.h macros */
#undef LOG_DEBUG
#undef LOG_INFO
#undef LOG_WARNING
#undef LOG_ERR

#define LOG_DEBUG(fmt, ...) \
    log_msg(LOG_LVL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  \
    log_msg(LOG_LVL_INFO,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  \
    log_msg(LOG_LVL_WARN,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   \
    log_msg(LOG_LVL_ERR,   __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* LOG_H */
