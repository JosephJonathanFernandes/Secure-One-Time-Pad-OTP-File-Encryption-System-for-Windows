/*
 * test_runner.h — Lightweight single-header test framework for the OTP project
 *
 * Zero external dependencies. Compiles with the same gcc -lbcrypt flags as
 * the main binary.
 *
 * Usage:
 *   #include "test_runner.h"
 *
 *   static void test_something(void) {
 *       TEST_ASSERT(1 + 1 == 2, "basic arithmetic");
 *       TEST_ASSERT_EQ_INT(42, compute_answer(), "answer");
 *   }
 *
 *   int main(void) {
 *       RUN_TEST(test_something);
 *       return TEST_SUMMARY();
 *   }
 */

#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H

#include <stdio.h>
#include <string.h>

/* ── Counters (file-scope, one TU owns them via TEST_RUNNER_IMPL) ─────────── */
#ifdef TEST_RUNNER_IMPL
int _tr_passed = 0;
int _tr_failed = 0;
const char *_tr_current = "(unknown)";
#else
extern int _tr_passed;
extern int _tr_failed;
extern const char *_tr_current;
#endif

/* ── Colour support (best-effort) ─────────────────────────────────────────── */
#define _TR_GREEN  "\x1b[32m"
#define _TR_RED    "\x1b[31m"
#define _TR_CYAN   "\x1b[36m"
#define _TR_RESET  "\x1b[0m"

/* ── Core assert macro ────────────────────────────────────────────────────── */
#define TEST_ASSERT(cond, msg)                                              \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr,                                                 \
                    _TR_RED "[FAIL]" _TR_RESET " %s :: %s\n"               \
                    "       Assertion: %s\n"                                \
                    "       At: %s:%d\n",                                   \
                    _tr_current, (msg), #cond, __FILE__, __LINE__);         \
            _tr_failed++;                                                   \
        } else {                                                            \
            printf(_TR_GREEN "[PASS]" _TR_RESET " %s :: %s\n",             \
                   _tr_current, (msg));                                     \
            _tr_passed++;                                                   \
        }                                                                   \
    } while (0)

/* ── Integer equality ─────────────────────────────────────────────────────── */
#define TEST_ASSERT_EQ_INT(expected, actual, msg)                           \
    do {                                                                    \
        long long _e = (long long)(expected);                               \
        long long _a = (long long)(actual);                                 \
        if (_e != _a) {                                                     \
            fprintf(stderr,                                                 \
                    _TR_RED "[FAIL]" _TR_RESET " %s :: %s\n"               \
                    "       Expected: %lld\n"                               \
                    "       Got:      %lld\n"                               \
                    "       At: %s:%d\n",                                   \
                    _tr_current, (msg), _e, _a, __FILE__, __LINE__);        \
            _tr_failed++;                                                   \
        } else {                                                            \
            printf(_TR_GREEN "[PASS]" _TR_RESET " %s :: %s\n",             \
                   _tr_current, (msg));                                     \
            _tr_passed++;                                                   \
        }                                                                   \
    } while (0)

/* ── Memory equality ──────────────────────────────────────────────────────── */
#define TEST_ASSERT_MEM_EQ(expected, actual, len, msg)                      \
    do {                                                                    \
        if (memcmp((expected), (actual), (len)) != 0) {                     \
            fprintf(stderr,                                                 \
                    _TR_RED "[FAIL]" _TR_RESET " %s :: %s "                \
                    "(memory mismatch, %zu bytes)\n"                        \
                    "       At: %s:%d\n",                                   \
                    _tr_current, (msg), (size_t)(len), __FILE__, __LINE__); \
            _tr_failed++;                                                   \
        } else {                                                            \
            printf(_TR_GREEN "[PASS]" _TR_RESET " %s :: %s\n",             \
                   _tr_current, (msg));                                     \
            _tr_passed++;                                                   \
        }                                                                   \
    } while (0)

/* ── Run a named test function ────────────────────────────────────────────── */
#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        _tr_current = #fn;                                                  \
        printf(_TR_CYAN "\n[TEST] %s\n" _TR_RESET, #fn);                   \
        fn();                                                               \
    } while (0)

/* ── Print summary and return exit code ───────────────────────────────────── */
#define TEST_SUMMARY()                                                      \
    (printf("\n============================================\n"              \
            " Results: " _TR_GREEN "%d passed" _TR_RESET                   \
            ", " _TR_RED "%d failed" _TR_RESET "\n"                        \
            "============================================\n",               \
            _tr_passed, _tr_failed),                                        \
     (_tr_failed > 0) ? 1 : 0)

#endif /* TEST_RUNNER_H */
