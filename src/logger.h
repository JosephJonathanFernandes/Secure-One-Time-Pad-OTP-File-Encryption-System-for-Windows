/*
 * logger.h — Logging subsystem for OTP encryption tool
 *
 * Provides thread-safe, tagged, optionally timestamped log output.
 * Tags: [INFO], [WARN], [ERROR], [SUCCESS]
 *
 * Usage:
 *   log_init(LOG_VERBOSE);
 *   LOG_INFO("Processing file: %s", filename);
 *   LOG_ERROR("Key size mismatch: expected %llu, got %llu", expected, got);
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Log levels ─────────────────────────────────────────────────────────── */
typedef enum {
    LOG_SILENT  = 0,   /* No output at all                      */
    LOG_NORMAL  = 1,   /* [INFO], [WARN], [ERROR], [SUCCESS]    */
    LOG_VERBOSE = 2    /* + timestamps and extra diagnostics     */
} LogLevel;

/* ── Global state (controlled by log_init) ──────────────────────────────── */
void log_init(LogLevel level);
LogLevel log_get_level(void);

/* ── Core logging functions ─────────────────────────────────────────────── */
void log_info   (const char *fmt, ...);
void log_warn   (const char *fmt, ...);
void log_error  (const char *fmt, ...);
void log_success(const char *fmt, ...);
void log_verbose(const char *fmt, ...);   /* Only printed at LOG_VERBOSE */

/* ── Convenience macros ─────────────────────────────────────────────────── */
#define LOG_INFO(...)    log_info(__VA_ARGS__)
#define LOG_WARN(...)    log_warn(__VA_ARGS__)
#define LOG_ERROR(...)   log_error(__VA_ARGS__)
#define LOG_SUCCESS(...) log_success(__VA_ARGS__)
#define LOG_VERBOSE(...) log_verbose(__VA_ARGS__)

/* ── Progress bar ───────────────────────────────────────────────────────── */
/*
 * Renders an inline ASCII progress bar to stdout.
 * Call with current bytes processed and total bytes.
 * Prints "\r" so the bar refreshes in place.
 */
void log_progress(unsigned long long done, unsigned long long total,
                  const char *label);

/* Finalise progress bar (prints newline after 100%) */
void log_progress_done(void);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */
