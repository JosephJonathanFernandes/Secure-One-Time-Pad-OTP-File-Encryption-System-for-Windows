/*
 * file_io.h — Safe file I/O and key lifecycle management for OTP tool
 *
 * Provides:
 *   - Safe file open with existence/permission checks
 *   - Large-file size query (>2 GB safe via _filelengthi64)
 *   - Key lock file mechanism to prevent accidental key reuse
 *   - Key size validation against target file
 *   - Secure file deletion (overwrite + delete)
 *   - Directory creation helpers
 */

#ifndef FILE_IO_H
#define FILE_IO_H

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Return codes ───────────────────────────────────────────────────────── */
typedef enum {
    FIO_OK               =  0,
    FIO_ERR_NOT_FOUND    = -1,   /* File does not exist             */
    FIO_ERR_OPEN         = -2,   /* fopen failed                    */
    FIO_ERR_SIZE         = -3,   /* Cannot determine file size      */
    FIO_ERR_KEY_MISMATCH = -4,   /* Key size != plaintext size      */
    FIO_ERR_KEY_LOCKED   = -5,   /* Key has already been used       */
    FIO_ERR_BAD_PARAM    = -6,   /* NULL or invalid argument        */
    FIO_ERR_MKDIR        = -7,   /* Directory creation failed       */
    FIO_ERR_DELETE       = -8    /* Secure delete failed            */
} FioStatus;

/* ── File open helpers ──────────────────────────────────────────────────── */
/*
 * fio_open_read()
 *   Opens an existing file for binary reading.
 *   Returns FIO_OK and sets *fp on success.
 *   Returns FIO_ERR_NOT_FOUND if file does not exist.
 *   Returns FIO_ERR_OPEN on other open errors.
 */
FioStatus fio_open_read(const char *path, FILE **fp);

/*
 * fio_open_write()
 *   Creates (or truncates) a file for binary writing.
 *   Returns FIO_ERR_OPEN if the file cannot be created.
 */
FioStatus fio_open_write(const char *path, FILE **fp);

/* ── File size ──────────────────────────────────────────────────────────── */
/*
 * fio_get_size()
 *   Returns the size of an open file handle in bytes via *size_out.
 *   Safe for files > 2 GB (uses _filelengthi64 / _ftelli64).
 */
FioStatus fio_get_size(FILE *fp, uint64_t *size_out);

/*
 * fio_path_exists()
 *   Returns 1 if path exists (any type), 0 otherwise.
 */
int fio_path_exists(const char *path);

/* ── Key size validation ────────────────────────────────────────────────── */
/*
 * fio_validate_key_size()
 *   Verifies that key_path refers to a file of at least `required_size` bytes.
 *   If the key file is smaller, returns FIO_ERR_KEY_MISMATCH.
 */
FioStatus fio_validate_key_size(const char *key_path, uint64_t required_size);

/* ── Key lock mechanism ─────────────────────────────────────────────────── */
/*
 * A lock file is a zero-byte sidecar with extension ".lock" placed next to
 * the key file (e.g., mykey.bin → mykey.bin.lock) once the key has been used.
 * Attempting to use a locked key fails with FIO_ERR_KEY_LOCKED.
 */

/*
 * fio_key_lock()
 *   Creates the lock file for `key_path`.
 *   Returns FIO_ERR_KEY_LOCKED if the lock already exists (key was used).
 *   Returns FIO_OK on success (lock file created).
 */
FioStatus fio_key_lock(const char *key_path);

/*
 * fio_key_is_locked()
 *   Returns 1 if the key's lock file exists, 0 otherwise.
 */
int fio_key_is_locked(const char *key_path);

/*
 * fio_key_unlock()
 *   Removes the lock file. Used only when an operation is rolled back.
 */
void fio_key_unlock(const char *key_path);

/* ── Secure delete ──────────────────────────────────────────────────────── */
/*
 * fio_secure_delete()
 *   Overwrites the file at `path` with zeros (3 passes) then deletes it.
 *   This is a best-effort operation on Windows (filesystem journalling,
 *   SSD wear-levelling, etc. may retain copies — document this limitation).
 *   Returns FIO_OK if the file was deleted (even if overwrite was partial).
 */
FioStatus fio_secure_delete(const char *path);

/* ── Directory helpers ──────────────────────────────────────────────────── */
/*
 * fio_ensure_dir()
 *   Creates `dir` (and any intermediate parents) if it does not exist.
 *   No-ops if already present.
 */
FioStatus fio_ensure_dir(const char *dir);

/* ── Lock path helper ───────────────────────────────────────────────────── */
/*
 * fio_lock_path()
 *   Fills `out` (capacity `out_size`) with "<key_path>.lock".
 *   Returns 0 on success, -1 if the buffer is too small.
 */
int fio_lock_path(const char *key_path, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* FILE_IO_H */
