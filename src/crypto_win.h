/*
 * crypto_win.h — Windows cryptographic primitives for OTP tool
 *
 * Provides:
 *   - CSPRNG key generation via BCryptGenRandom
 *   - SHA-256 file/buffer hashing via BCrypt hash APIs
 *   - Secure memory zeroing via SecureZeroMemory
 *
 * All functions return CRYPTO_OK (0) on success and a negative error code
 * on failure.  Error codes defined as CRYPTO_ERR_* constants below.
 *
 * IMPORTANT: Never store or log key material. Callers are responsible for
 * zeroing sensitive buffers using crypto_secure_zero() after use.
 */

#ifndef CRYPTO_WIN_H
#define CRYPTO_WIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── SHA-256 digest size ────────────────────────────────────────────────── */
#define SHA256_DIGEST_BYTES  32u

/* ── Return codes ───────────────────────────────────────────────────────── */
typedef enum {
    CRYPTO_OK              =  0,
    CRYPTO_ERR_BCRYPT_OPEN = -1,   /* Failed to open BCrypt algorithm */
    CRYPTO_ERR_RNG         = -2,   /* BCryptGenRandom failed          */
    CRYPTO_ERR_HASH_INIT   = -3,   /* Hash object allocation failed   */
    CRYPTO_ERR_HASH_DATA   = -4,   /* BCryptHashData failed           */
    CRYPTO_ERR_HASH_FINISH = -5,   /* BCryptFinishHash failed         */
    CRYPTO_ERR_IO          = -6,   /* File read error during hashing  */
    CRYPTO_ERR_BAD_PARAM   = -7    /* NULL or invalid argument        */
} CryptoStatus;

/* ── Key generation ─────────────────────────────────────────────────────── */
/*
 * crypto_gen_key_to_file()
 *
 * Generates `size` bytes of cryptographically secure random data and
 * writes them to `key_path`.  The data is generated using BCryptGenRandom
 * in chunks to avoid large stack allocations.
 *
 * Parameters:
 *   key_path  — destination path for the key file (must not exist)
 *   size      — exact number of bytes to generate
 *
 * Returns CRYPTO_OK on success, or a negative CryptoStatus on failure.
 */
CryptoStatus crypto_gen_key_to_file(const char *key_path, uint64_t size);

/*
 * crypto_fill_buffer()
 *
 * Fills `buf` with `len` bytes of cryptographically secure random data.
 * Suitable for small in-memory buffers.  Do NOT use for large keys —
 * use crypto_gen_key_to_file() instead.
 */
CryptoStatus crypto_fill_buffer(unsigned char *buf, size_t len);

/* ── SHA-256 hashing ─────────────────────────────────────────────────────── */
/*
 * crypto_sha256_file()
 *
 * Computes the SHA-256 digest of the file at `path` and stores it in
 * `digest_out` (must be at least SHA256_DIGEST_BYTES bytes).
 *
 * The file is read in 8 KB chunks; it never loads the full file into memory.
 */
CryptoStatus crypto_sha256_file(const char *path,
                                 unsigned char digest_out[SHA256_DIGEST_BYTES]);

/*
 * crypto_sha256_buffer()
 *
 * Computes the SHA-256 digest of `data` (length `len`) and stores it in
 * `digest_out`.
 */
CryptoStatus crypto_sha256_buffer(const unsigned char *data, size_t len,
                                   unsigned char digest_out[SHA256_DIGEST_BYTES]);

/* ── Secure memory helpers ──────────────────────────────────────────────── */
/*
 * crypto_secure_zero()
 *
 * Securely zeroes `len` bytes at `ptr` using SecureZeroMemory.
 * Unlike memset(), this call is guaranteed not to be optimised away.
 */
void crypto_secure_zero(void *ptr, size_t len);

/*
 * crypto_hex_string()
 *
 * Converts `len` bytes of binary data to a lowercase hex string.
 * `hex_out` must hold at least 2*len + 1 bytes.
 */
void crypto_hex_string(const unsigned char *data, size_t len, char *hex_out);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_WIN_H */
