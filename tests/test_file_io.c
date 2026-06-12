/*
 * test_file_io.c — Unit tests for the file I/O and key lifecycle layer
 *
 * Covers:
 *   - Key lock file creation and detection
 *   - fio_key_is_locked before and after locking
 *   - fio_key_unlock rollback removes lock file
 *   - fio_secure_delete removes the file
 *   - fio_validate_key_size: exact match, too small, missing file
 *   - fio_path_exists: existing vs non-existing paths
 *   - fio_ensure_dir: creates a directory
 *   - fio_open_read: missing file returns FIO_ERR_NOT_FOUND
 *   - fio_get_size: returns correct byte count
 */

#define TEST_RUNNER_IMPL
#include "test_runner.h"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../src/file_io.h"

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int write_bytes(const char *path, size_t n)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned char b = (unsigned char)(i & 0xFF);
        fwrite(&b, 1, 1, fp);
    }
    fclose(fp);
    return 0;
}

static void nuke(const char *path)
{
    remove(path);
}

static void nuke_key(const char *path)
{
    char lock[MAX_PATH];
    remove(path);
    if (fio_lock_path(path, lock, sizeof(lock)) == 0) remove(lock);
}

/* ── Tests ───────────────────────────────────────────────────────────────── */

static void test_key_lock_lifecycle(void)
{
    const char *key = "tests\\fio_test.key";
    nuke_key(key);
    write_bytes(key, 64);

    /* Before locking: should not be locked */
    TEST_ASSERT(!fio_key_is_locked(key),
                "key is NOT locked before fio_key_lock()");

    /* Lock the key */
    FioStatus s = fio_key_lock(key);
    TEST_ASSERT_EQ_INT(FIO_OK, s, "fio_key_lock() returns FIO_OK");
    TEST_ASSERT(fio_key_is_locked(key),
                "key IS locked after fio_key_lock()");

    /* Second lock attempt must fail */
    FioStatus s2 = fio_key_lock(key);
    TEST_ASSERT_EQ_INT(FIO_ERR_KEY_LOCKED, s2,
                       "second fio_key_lock() returns FIO_ERR_KEY_LOCKED");

    nuke_key(key);
}

static void test_key_unlock_removes_lock(void)
{
    const char *key = "tests\\fio_unlock_test.key";
    nuke_key(key);
    write_bytes(key, 32);

    fio_key_lock(key);
    TEST_ASSERT(fio_key_is_locked(key), "key locked before unlock");

    fio_key_unlock(key);
    TEST_ASSERT(!fio_key_is_locked(key),
                "key is NOT locked after fio_key_unlock()");

    nuke_key(key);
}

static void test_secure_delete(void)
{
    const char *path = "tests\\fio_secdel_test.bin";
    write_bytes(path, 4096);

    TEST_ASSERT(fio_path_exists(path), "file exists before secure delete");

    FioStatus s = fio_secure_delete(path);
    TEST_ASSERT_EQ_INT(FIO_OK, s, "fio_secure_delete returns FIO_OK");
    TEST_ASSERT(!fio_path_exists(path),
                "file does NOT exist after secure delete");
}

static void test_validate_key_size(void)
{
    const char *key = "tests\\fio_keysize_test.key";
    nuke(key);

    /* Create a 64-byte key file */
    write_bytes(key, 64);

    /* Exact match: OK */
    TEST_ASSERT_EQ_INT(FIO_OK,
                       fio_validate_key_size(key, 64),
                       "key size == required → FIO_OK");

    /* Key larger than required: OK (OTP allows partial key use) */
    TEST_ASSERT_EQ_INT(FIO_OK,
                       fio_validate_key_size(key, 32),
                       "key size > required → FIO_OK");

    /* Key smaller than required: mismatch */
    TEST_ASSERT_EQ_INT(FIO_ERR_KEY_MISMATCH,
                       fio_validate_key_size(key, 128),
                       "key size < required → FIO_ERR_KEY_MISMATCH");

    nuke(key);
}

static void test_validate_key_missing_file(void)
{
    FioStatus s = fio_validate_key_size("tests\\does_not_exist.key", 64);
    TEST_ASSERT(s != FIO_OK,
                "missing key file → non-OK status");
}

static void test_path_exists(void)
{
    const char *tmp = "tests\\fio_exists_test.bin";
    write_bytes(tmp, 1);

    TEST_ASSERT(fio_path_exists(tmp) == 1,
                "fio_path_exists returns 1 for existing file");
    nuke(tmp);
    TEST_ASSERT(fio_path_exists(tmp) == 0,
                "fio_path_exists returns 0 for deleted file");
}

static void test_open_read_missing_file(void)
{
    FILE *fp = NULL;
    FioStatus s = fio_open_read("tests\\no_such_file.bin", &fp);
    TEST_ASSERT_EQ_INT(FIO_ERR_NOT_FOUND, s,
                       "missing file → FIO_ERR_NOT_FOUND");
    TEST_ASSERT(fp == NULL, "fp is NULL on failure");
}

static void test_get_size(void)
{
    const char *tmp = "tests\\fio_size_test.bin";
    write_bytes(tmp, 137); /* odd size on purpose */

    FILE *fp = NULL;
    FioStatus os = fio_open_read(tmp, &fp);
    TEST_ASSERT_EQ_INT(FIO_OK, os, "open succeeds");

    uint64_t sz = 0;
    FioStatus gs = fio_get_size(fp, &sz);
    fclose(fp);
    nuke(tmp);

    TEST_ASSERT_EQ_INT(FIO_OK, gs, "fio_get_size returns FIO_OK");
    TEST_ASSERT_EQ_INT(137, (long long)sz,
                       "fio_get_size returns correct byte count (137)");
}

static void test_ensure_dir_creates_directory(void)
{
    const char *dir = "tests\\fio_newdir_test";
    RemoveDirectoryA(dir); /* clean up stale dir */

    FioStatus s = fio_ensure_dir(dir);
    TEST_ASSERT_EQ_INT(FIO_OK, s, "fio_ensure_dir returns FIO_OK");
    TEST_ASSERT(fio_path_exists(dir), "directory was created");

    /* Idempotent: calling again must succeed */
    FioStatus s2 = fio_ensure_dir(dir);
    TEST_ASSERT_EQ_INT(FIO_OK, s2,
                       "fio_ensure_dir on existing dir is idempotent");

    RemoveDirectoryA(dir);
}

static void test_null_args_rejected(void)
{
    FILE *fp = NULL;
    uint64_t sz = 0;

    TEST_ASSERT_EQ_INT(FIO_ERR_BAD_PARAM,
                       fio_open_read(NULL, &fp),
                       "NULL path → FIO_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(FIO_ERR_BAD_PARAM,
                       fio_open_read("x", NULL),
                       "NULL fp → FIO_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(FIO_ERR_BAD_PARAM,
                       fio_get_size(NULL, &sz),
                       "NULL fp in get_size → FIO_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(FIO_ERR_BAD_PARAM,
                       fio_validate_key_size(NULL, 64),
                       "NULL path in validate → FIO_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(FIO_ERR_BAD_PARAM,
                       fio_secure_delete(NULL),
                       "NULL path in secure_delete → FIO_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(FIO_ERR_BAD_PARAM,
                       fio_ensure_dir(NULL),
                       "NULL path in ensure_dir → FIO_ERR_BAD_PARAM");
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void)
{
    printf("File I/O and Key Lifecycle Tests\n");
    printf("==================================\n");

    /* Ensure tests/ exists so our temp files can be created */
    fio_ensure_dir("tests");

    RUN_TEST(test_key_lock_lifecycle);
    RUN_TEST(test_key_unlock_removes_lock);
    RUN_TEST(test_secure_delete);
    RUN_TEST(test_validate_key_size);
    RUN_TEST(test_validate_key_missing_file);
    RUN_TEST(test_path_exists);
    RUN_TEST(test_open_read_missing_file);
    RUN_TEST(test_get_size);
    RUN_TEST(test_ensure_dir_creates_directory);
    RUN_TEST(test_null_args_rejected);

    return TEST_SUMMARY();
}
