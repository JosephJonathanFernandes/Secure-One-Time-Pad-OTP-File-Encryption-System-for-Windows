/*
 * logger.c — Logging subsystem implementation
 *
 * Uses Windows ANSI escape codes for coloured output when the terminal
 * supports it (Windows 10 1511+ with ENABLE_VIRTUAL_TERMINAL_PROCESSING).
 * Falls back to plain text if the console does not support VT sequences.
 */

#include "logger.h"

#include <stdio.h>
#include <time.h>
#include <string.h>

/* Windows header for VT processing detection */
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* ── Internal state ─────────────────────────────────────────────────────── */
static LogLevel  g_level        = LOG_NORMAL;
static int       g_colors_ok    = 0;   /* 1 if ANSI colours are supported  */
static int       g_progress_active = 0; /* 1 while a progress bar is shown */

/* ── ANSI colour codes ──────────────────────────────────────────────────── */
#define COL_RESET   "\x1b[0m"
#define COL_CYAN    "\x1b[36m"
#define COL_YELLOW  "\x1b[33m"
#define COL_RED     "\x1b[31m"
#define COL_GREEN   "\x1b[32m"
#define COL_GREY    "\x1b[90m"
#define COL_WHITE   "\x1b[97m"
#define COL_BLUE    "\x1b[34m"

/* ── Colour support detection ───────────────────────────────────────────── */
static void detect_color_support(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) return;

    /* Enable ANSI escape processing */
    if (SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        g_colors_ok = 1;
    }
}

/* ── Public: initialise ─────────────────────────────────────────────────── */
void log_init(LogLevel level)
{
    g_level = level;
    detect_color_support();
}

LogLevel log_get_level(void)
{
    return g_level;
}

/* ── Internal: timestamp string ─────────────────────────────────────────── */
static void get_timestamp(char *buf, size_t len)
{
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    if (tm_info) {
        strftime(buf, len, "%H:%M:%S", tm_info);
    } else {
        strncpy(buf, "??:??:??", len - 1);
        buf[len - 1] = '\0';
    }
}

/* ── Internal: generic log emitter ─────────────────────────────────────── */
static void emit_log(FILE *stream,
                     const char *col_tag,
                     const char *label,
                     const char *fmt,
                     va_list args)
{
    /* If a progress bar is active, clear the line first */
    if (g_progress_active) {
        fprintf(stdout, "\r%*s\r", 79, "");
        fflush(stdout);
        g_progress_active = 0;
    }

    if (g_level >= LOG_VERBOSE) {
        char ts[16];
        get_timestamp(ts, sizeof(ts));
        if (g_colors_ok) {
            fprintf(stream, "%s%s%s ", COL_GREY, ts, COL_RESET);
        } else {
            fprintf(stream, "[%s] ", ts);
        }
    }

    if (g_colors_ok) {
        fprintf(stream, "%s%s%s ", col_tag, label, COL_RESET);
    } else {
        fprintf(stream, "%s ", label);
    }

    vfprintf(stream, fmt, args);
    fprintf(stream, "\n");
    fflush(stream);
}

/* ── Public logging functions ────────────────────────────────────────────── */
void log_info(const char *fmt, ...)
{
    if (g_level < LOG_NORMAL) return;
    va_list args;
    va_start(args, fmt);
    emit_log(stdout, COL_CYAN, "[INFO]   ", fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...)
{
    if (g_level < LOG_NORMAL) return;
    va_list args;
    va_start(args, fmt);
    emit_log(stderr, COL_YELLOW, "[WARN]   ", fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...)
{
    if (g_level < LOG_NORMAL) return;
    va_list args;
    va_start(args, fmt);
    emit_log(stderr, COL_RED, "[ERROR]  ", fmt, args);
    va_end(args);
}

void log_success(const char *fmt, ...)
{
    if (g_level < LOG_NORMAL) return;
    va_list args;
    va_start(args, fmt);
    emit_log(stdout, COL_GREEN, "[SUCCESS]", fmt, args);
    va_end(args);
}

void log_verbose(const char *fmt, ...)
{
    if (g_level < LOG_VERBOSE) return;
    va_list args;
    va_start(args, fmt);
    emit_log(stdout, COL_GREY, "[DEBUG]  ", fmt, args);
    va_end(args);
}

/* ── Progress bar ───────────────────────────────────────────────────────── */
void log_progress(unsigned long long done,
                  unsigned long long total,
                  const char *label)
{
    if (g_level < LOG_NORMAL) return;
    if (total == 0) return;

    const int BAR_WIDTH = 40;
    double pct = (double)done / (double)total;
    int filled = (int)(pct * BAR_WIDTH);

    /* Build bar string */
    char bar[BAR_WIDTH + 1];
    for (int i = 0; i < BAR_WIDTH; i++) {
        bar[i] = (i < filled) ? '=' : '-';
    }
    bar[BAR_WIDTH] = '\0';
    if (filled > 0 && filled < BAR_WIDTH) {
        bar[filled - 1] = '>';
    }

    /* Size helper: display MB or KB */
    double done_mb  = (double)done  / (1024.0 * 1024.0);
    double total_mb = (double)total / (1024.0 * 1024.0);

    if (g_colors_ok) {
        fprintf(stdout,
                "\r%s%s%s [%s%s%s] %5.1f%% %6.2f/%6.2f MB",
                COL_BLUE, label, COL_RESET,
                COL_GREEN, bar, COL_RESET,
                pct * 100.0,
                done_mb, total_mb);
    } else {
        fprintf(stdout,
                "\r%s [%s] %5.1f%% %.2f/%.2f MB",
                label, bar, pct * 100.0, done_mb, total_mb);
    }
    fflush(stdout);
    g_progress_active = 1;
}

void log_progress_done(void)
{
    if (g_progress_active) {
        fprintf(stdout, "\n");
        fflush(stdout);
        g_progress_active = 0;
    }
}
