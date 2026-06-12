/*
 * file_io.c — Safe file I/O and key lifecycle management
 */

#include "file_io.h"
#include "logger.h"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <direct.h>   /* _mkdir */
#include <io.h>       /* _filelengthi64 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

/* ── fio_path_exists ────────────────────────────────────────────────────── */
int fio_path_exists(const char *path)
{
    if (!path) return 0;
    struct _stat64 st;
    return (_stat64(path, &st) == 0) ? 1 : 0;
}

/* ── fio_open_read ──────────────────────────────────────────────────────── */
FioStatus fio_open_read(const char *path, FILE **fp)
{
    if (!path || !fp) return FIO_ERR_BAD_PARAM;

    if (!fio_path_exists(path)) {
        LOG_ERROR("File not found: %s", path);
        return FIO_ERR_NOT_FOUND;
    }

    *fp = fopen(path, "rb");
    if (!*fp) {
        LOG_ERROR("Cannot open file for reading: %s (errno=%d)", path, errno);
        return FIO_ERR_OPEN;
    }
    return FIO_OK;
}

/* ── fio_open_write ─────────────────────────────────────────────────────── */
FioStatus fio_open_write(const char *path, FILE **fp)
{
    if (!path || !fp) return FIO_ERR_BAD_PARAM;

    *fp = fopen(path, "wb");
    if (!*fp) {
        LOG_ERROR("Cannot open file for writing: %s (errno=%d)", path, errno);
        return FIO_ERR_OPEN;
    }
    return FIO_OK;
}

/* ── fio_get_size ───────────────────────────────────────────────────────── */
FioStatus fio_get_size(FILE *fp, uint64_t *size_out)
{
    if (!fp || !size_out) return FIO_ERR_BAD_PARAM;

    /* Save current position */
    long long saved_pos = _ftelli64(fp);
    if (saved_pos < 0) {
        LOG_ERROR("_ftelli64 failed (errno=%d)", errno);
        return FIO_ERR_SIZE;
    }

    /* Seek to end */
    if (_fseeki64(fp, 0, SEEK_END) != 0) {
        LOG_ERROR("_fseeki64 failed (errno=%d)", errno);
        return FIO_ERR_SIZE;
    }

    long long size = _ftelli64(fp);
    if (size < 0) {
        LOG_ERROR("_ftelli64(end) failed (errno=%d)", errno);
        _fseeki64(fp, saved_pos, SEEK_SET);
        return FIO_ERR_SIZE;
    }

    /* Restore position */
    _fseeki64(fp, saved_pos, SEEK_SET);

    *size_out = (uint64_t)size;
    return FIO_OK;
}

/* ── fio_validate_key_size ──────────────────────────────────────────────── */
FioStatus fio_validate_key_size(const char *key_path, uint64_t required_size)
{
    if (!key_path) return FIO_ERR_BAD_PARAM;

    FILE *fp = NULL;
    FioStatus s = fio_open_read(key_path, &fp);
    if (s != FIO_OK) return s;

    uint64_t key_size = 0;
    s = fio_get_size(fp, &key_size);
    fclose(fp);
    if (s != FIO_OK) return s;

    if (key_size < required_size) {
        LOG_ERROR("Key too small: file needs %llu bytes, key is %llu bytes",
                  (unsigned long long)required_size, (unsigned long long)key_size);
        return FIO_ERR_KEY_MISMATCH;
    }

    LOG_VERBOSE("Key size OK: %llu bytes (required %llu)",
                (unsigned long long)key_size, (unsigned long long)required_size);
    return FIO_OK;
}

/* ── Lock path helper ───────────────────────────────────────────────────── */
int fio_lock_path(const char *key_path, char *out, size_t out_size)
{
    if (!key_path || !out || out_size == 0) return -1;
    int written = snprintf(out, out_size, "%s.lock", key_path);
    if (written < 0 || (size_t)written >= out_size) return -1;
    return 0;
}

/* ── fio_key_is_locked ──────────────────────────────────────────────────── */
int fio_key_is_locked(const char *key_path)
{
    char lock[MAX_PATH];
    if (fio_lock_path(key_path, lock, sizeof(lock)) != 0) return 0;
    return fio_path_exists(lock);
}

/* ── fio_key_lock ───────────────────────────────────────────────────────── */
FioStatus fio_key_lock(const char *key_path)
{
    if (!key_path) return FIO_ERR_BAD_PARAM;

    /* Reject if already locked */
    if (fio_key_is_locked(key_path)) {
        LOG_ERROR("Key is already locked (previously used): %s", key_path);
        LOG_WARN("ONE-TIME PAD RULE VIOLATED: Never reuse a key!");
        LOG_WARN("Generate a new key with: otp.exe -g <size> <keyfile>");
        return FIO_ERR_KEY_LOCKED;
    }

    char lock[MAX_PATH];
    if (fio_lock_path(key_path, lock, sizeof(lock)) != 0) {
        LOG_ERROR("Lock path too long for key: %s", key_path);
        return FIO_ERR_OPEN;
    }

    FILE *fp = fopen(lock, "wb");
    if (!fp) {
        LOG_ERROR("Cannot create lock file: %s (errno=%d)", lock, errno);
        return FIO_ERR_OPEN;
    }

    /* Write a descriptive notice inside the lock file */
    fprintf(fp, "OTP key locked after use. Do NOT reuse this key.\r\nKey: %s\r\n",
            key_path);
    fclose(fp);

    LOG_VERBOSE("Key locked: %s", lock);
    return FIO_OK;
}

/* ── fio_key_unlock ─────────────────────────────────────────────────────── */
void fio_key_unlock(const char *key_path)
{
    char lock[MAX_PATH];
    if (fio_lock_path(key_path, lock, sizeof(lock)) != 0) return;
    remove(lock);
    LOG_VERBOSE("Key lock removed (rollback): %s", lock);
}

/* ── fio_secure_delete ──────────────────────────────────────────────────── */
FioStatus fio_secure_delete(const char *path)
{
    if (!path) return FIO_ERR_BAD_PARAM;
    if (!fio_path_exists(path)) return FIO_OK; /* Already gone */

    /* Open in read+write mode to overwrite content */
    FILE *fp = fopen(path, "r+b");
    if (!fp) {
        LOG_WARN("Could not open '%s' for secure overwrite, will attempt plain delete", path);
        goto plain_delete;
    }

    uint64_t file_size = 0;
    if (fio_get_size(fp, &file_size) != FIO_OK || file_size == 0) {
        fclose(fp);
        goto plain_delete;
    }

    /* Three overwrite passes:
     *   Pass 1: all 0x00
     *   Pass 2: all 0xFF
     *   Pass 3: all 0x00  (leave zeroed)
     */
    static const unsigned char patterns[3] = {0x00, 0xFF, 0x00};
    unsigned char chunk[4096];

    for (int pass = 0; pass < 3; pass++) {
        memset(chunk, patterns[pass], sizeof(chunk));
        rewind(fp);
        fflush(fp);

        uint64_t remaining = file_size;
        while (remaining > 0) {
            size_t to_write = (remaining > sizeof(chunk)) ? sizeof(chunk) : (size_t)remaining;
            size_t written  = fwrite(chunk, 1, to_write, fp);
            if (written == 0) break;
            remaining -= written;
        }
        fflush(fp);
    }

    fclose(fp);
    LOG_VERBOSE("Secure overwrite complete (3 passes): %s", path);

plain_delete:
    if (remove(path) != 0) {
        LOG_ERROR("Failed to delete file: %s (errno=%d)", path, errno);
        return FIO_ERR_DELETE;
    }

    LOG_SUCCESS("Securely deleted: %s", path);
    return FIO_OK;
}

/* ── fio_ensure_dir ─────────────────────────────────────────────────────── */
FioStatus fio_ensure_dir(const char *dir)
{
    if (!dir) return FIO_ERR_BAD_PARAM;
    if (fio_path_exists(dir)) return FIO_OK;

    /* Use Windows CreateDirectoryA which creates only one level.
     * For nested paths we walk the string and create each component. */
    char buf[MAX_PATH];
    strncpy(buf, dir, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Normalise to backslash */
    for (char *p = buf; *p; p++) {
        if (*p == '/') *p = '\\';
    }

    /* Walk and create each path component */
    for (char *p = buf + 1; *p; p++) {
        if (*p == '\\') {
            *p = '\0';
            if (!fio_path_exists(buf)) {
                if (!CreateDirectoryA(buf, NULL)) {
                    DWORD err = GetLastError();
                    if (err != ERROR_ALREADY_EXISTS) {
                        LOG_ERROR("CreateDirectoryA failed for '%s' (err=%lu)", buf, err);
                        return FIO_ERR_MKDIR;
                    }
                }
            }
            *p = '\\';
        }
    }

    /* Create the final component */
    if (!fio_path_exists(buf)) {
        if (!CreateDirectoryA(buf, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_ALREADY_EXISTS) {
                LOG_ERROR("CreateDirectoryA failed for '%s' (err=%lu)", buf, err);
                return FIO_ERR_MKDIR;
            }
        }
    }

    LOG_VERBOSE("Directory ensured: %s", dir);
    return FIO_OK;
}
