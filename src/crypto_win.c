/*
 * crypto_win.c — Windows cryptographic primitives implementation
 *
 * Uses the Windows CNG (Cryptography Next Generation) API via bcrypt.h.
 * Link with: -lbcrypt (MinGW) or bcrypt.lib (MSVC).
 *
 * BCryptGenRandom is FIPS 140-2 compliant when using
 * BCRYPT_USE_SYSTEM_PREFERRED_RNG.
 */

#include "crypto_win.h"
#include "logger.h"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Link bcrypt at compile time.
 * MinGW: add -lbcrypt to LDFLAGS.
 * MSVC:  add bcrypt.lib to linker inputs.
 * The pragma below handles MSVC automatically. */
#ifdef _MSC_VER
#  pragma comment(lib, "bcrypt.lib")
#endif

/* ── Internal constants ─────────────────────────────────────────────────── */
#define CHUNK_SIZE       (8u * 1024u)    /* 8 KB I/O and RNG chunk size */
#define NT_SUCCESS(s)    ((NTSTATUS)(s) >= 0)

/* ── Secure memory helpers ──────────────────────────────────────────────── */
void crypto_secure_zero(void *ptr, size_t len)
{
    if (ptr && len > 0) {
        SecureZeroMemory(ptr, len);
    }
}

void crypto_hex_string(const unsigned char *data, size_t len, char *hex_out)
{
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex_out[i * 2]     = hex_chars[(data[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    hex_out[len * 2] = '\0';
}

/* ── crypto_fill_buffer ─────────────────────────────────────────────────── */
CryptoStatus crypto_fill_buffer(unsigned char *buf, size_t len)
{
    if (!buf || len == 0) return CRYPTO_ERR_BAD_PARAM;

    NTSTATUS status = BCryptGenRandom(
        NULL,                          /* use system default RNG provider  */
        (PUCHAR)buf,
        (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!NT_SUCCESS(status)) {
        LOG_ERROR("BCryptGenRandom failed with NTSTATUS 0x%08lX", (unsigned long)status);
        return CRYPTO_ERR_RNG;
    }
    return CRYPTO_OK;
}

/* ── crypto_gen_key_to_file ─────────────────────────────────────────────── */
CryptoStatus crypto_gen_key_to_file(const char *key_path, uint64_t size)
{
    if (!key_path || size == 0) return CRYPTO_ERR_BAD_PARAM;

    FILE *fp = fopen(key_path, "wb");
    if (!fp) {
        LOG_ERROR("Cannot create key file: %s", key_path);
        return CRYPTO_ERR_IO;
    }

    unsigned char chunk[CHUNK_SIZE];
    uint64_t remaining = size;
    CryptoStatus ret = CRYPTO_OK;

    LOG_INFO("Generating %llu bytes of cryptographically secure key material...",
             (unsigned long long)size);

    while (remaining > 0) {
        size_t this_chunk = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)remaining;

        NTSTATUS status = BCryptGenRandom(
            NULL,
            (PUCHAR)chunk,
            (ULONG)this_chunk,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        if (!NT_SUCCESS(status)) {
            LOG_ERROR("BCryptGenRandom failed during key generation (NTSTATUS 0x%08lX)",
                      (unsigned long)status);
            ret = CRYPTO_ERR_RNG;
            goto cleanup;
        }

        if (fwrite(chunk, 1, this_chunk, fp) != this_chunk) {
            LOG_ERROR("Failed to write key bytes to file: %s", key_path);
            ret = CRYPTO_ERR_IO;
            goto cleanup;
        }

        remaining -= this_chunk;
    }

cleanup:
    /* Always zero the chunk buffer before leaving — key material is sensitive */
    crypto_secure_zero(chunk, sizeof(chunk));
    fclose(fp);

    if (ret != CRYPTO_OK) {
        /* Remove partial key file */
        remove(key_path);
    }

    return ret;
}

/* ── Internal: open BCrypt SHA-256 algorithm handle ─────────────────────── */
static CryptoStatus open_sha256_provider(BCRYPT_ALG_HANDLE *phAlg)
{
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        phAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0
    );
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("BCryptOpenAlgorithmProvider(SHA256) failed: 0x%08lX",
                  (unsigned long)status);
        return CRYPTO_ERR_BCRYPT_OPEN;
    }
    return CRYPTO_OK;
}

/* ── Internal: compute SHA-256 using an open FILE* ──────────────────────── */
static CryptoStatus sha256_from_fp(BCRYPT_ALG_HANDLE hAlg,
                                    FILE *fp,
                                    unsigned char digest_out[SHA256_DIGEST_BYTES])
{
    CryptoStatus ret = CRYPTO_OK;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hash_obj_size = 0, result_size = 0;
    PBYTE hash_obj = NULL;
    unsigned char chunk[CHUNK_SIZE];

    /* Query the hash object buffer size */
    NTSTATUS status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&hash_obj_size,
        sizeof(DWORD),
        &result_size,
        0
    );
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("BCryptGetProperty(OBJECT_LENGTH) failed: 0x%08lX",
                  (unsigned long)status);
        ret = CRYPTO_ERR_HASH_INIT;
        goto done;
    }

    hash_obj = (PBYTE)malloc(hash_obj_size);
    if (!hash_obj) {
        LOG_ERROR("Out of memory allocating SHA-256 hash object");
        ret = CRYPTO_ERR_HASH_INIT;
        goto done;
    }

    status = BCryptCreateHash(hAlg, &hHash, hash_obj, hash_obj_size, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("BCryptCreateHash failed: 0x%08lX", (unsigned long)status);
        ret = CRYPTO_ERR_HASH_INIT;
        goto done;
    }

    /* Feed data in chunks */
    size_t bytes_read;
    while ((bytes_read = fread(chunk, 1, CHUNK_SIZE, fp)) > 0) {
        status = BCryptHashData(hHash, (PBYTE)chunk, (ULONG)bytes_read, 0);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("BCryptHashData failed: 0x%08lX", (unsigned long)status);
            ret = CRYPTO_ERR_HASH_DATA;
            goto done;
        }
    }

    if (ferror(fp)) {
        LOG_ERROR("File read error during SHA-256 computation");
        ret = CRYPTO_ERR_IO;
        goto done;
    }

    status = BCryptFinishHash(hHash, (PBYTE)digest_out, SHA256_DIGEST_BYTES, 0);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("BCryptFinishHash failed: 0x%08lX", (unsigned long)status);
        ret = CRYPTO_ERR_HASH_FINISH;
        goto done;
    }

done:
    crypto_secure_zero(chunk, sizeof(chunk));
    if (hHash)    BCryptDestroyHash(hHash);
    if (hash_obj) { crypto_secure_zero(hash_obj, hash_obj_size); free(hash_obj); }
    return ret;
}

/* ── crypto_sha256_file ─────────────────────────────────────────────────── */
CryptoStatus crypto_sha256_file(const char *path,
                                 unsigned char digest_out[SHA256_DIGEST_BYTES])
{
    if (!path || !digest_out) return CRYPTO_ERR_BAD_PARAM;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERROR("Cannot open file for hashing: %s", path);
        return CRYPTO_ERR_IO;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    CryptoStatus ret = open_sha256_provider(&hAlg);
    if (ret != CRYPTO_OK) { fclose(fp); return ret; }

    ret = sha256_from_fp(hAlg, fp, digest_out);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    fclose(fp);
    return ret;
}

/* ── crypto_sha256_buffer ───────────────────────────────────────────────── */
CryptoStatus crypto_sha256_buffer(const unsigned char *data, size_t len,
                                   unsigned char digest_out[SHA256_DIGEST_BYTES])
{
    if (!data || !digest_out) return CRYPTO_ERR_BAD_PARAM;

    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE hash_obj = NULL;
    DWORD hash_obj_size = 0, result_size = 0;
    CryptoStatus ret = CRYPTO_OK;

    CryptoStatus s = open_sha256_provider(&hAlg);
    if (s != CRYPTO_OK) return s;

    NTSTATUS status = BCryptGetProperty(
        hAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&hash_obj_size, sizeof(DWORD), &result_size, 0);
    if (!NT_SUCCESS(status)) { ret = CRYPTO_ERR_HASH_INIT; goto done; }

    hash_obj = (PBYTE)malloc(hash_obj_size);
    if (!hash_obj) { ret = CRYPTO_ERR_HASH_INIT; goto done; }

    status = BCryptCreateHash(hAlg, &hHash, hash_obj, hash_obj_size, NULL, 0, 0);
    if (!NT_SUCCESS(status)) { ret = CRYPTO_ERR_HASH_INIT; goto done; }

    status = BCryptHashData(hHash, (PBYTE)data, (ULONG)len, 0);
    if (!NT_SUCCESS(status)) { ret = CRYPTO_ERR_HASH_DATA; goto done; }

    status = BCryptFinishHash(hHash, (PBYTE)digest_out, SHA256_DIGEST_BYTES, 0);
    if (!NT_SUCCESS(status)) { ret = CRYPTO_ERR_HASH_FINISH; goto done; }

done:
    if (hHash)    BCryptDestroyHash(hHash);
    if (hash_obj) { crypto_secure_zero(hash_obj, hash_obj_size); free(hash_obj); }
    if (hAlg)     BCryptCloseAlgorithmProvider(hAlg, 0);
    return ret;
}
