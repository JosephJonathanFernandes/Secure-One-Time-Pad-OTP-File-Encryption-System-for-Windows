/*
 * otp.h — Core One-Time Pad encrypt/decrypt engine
 *
 * Implements XOR-based OTP encryption with:
 *   - Streaming 8 KB chunk processing (no full-file RAM load)
 *   - Custom binary file header with magic bytes, plaintext size, and SHA-256
 *   - Progress callback support
 *   - Typed error codes for all failure modes
 *   - Post-decrypt SHA-256 integrity verification
 *
 * FILE FORMAT (.enc):
 * ┌─────────────────────────────────────────────────────┐
 * │ Offset │ Size │ Field                               │
 * │   0    │  4   │ Magic: "OTP\x01"                   │
 * │   4    │  8   │ Original plaintext size (uint64 LE) │
 * │  12    │  32  │ SHA-256 of original plaintext       │
 * │  44    │  8   │ Reserved (zeroed)                   │
 * │  52    │  N   │ Ciphertext (N = plaintext_size)     │
 * └─────────────────────────────────────────────────────┘
 */

#ifndef OTP_H
#define OTP_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Header constants ───────────────────────────────────────────────────── */
#define OTP_MAGIC             "OTP\x01"
#define OTP_MAGIC_SIZE        4u
#define OTP_HEADER_SIZE       52u     /* Total header size in bytes */
#define OTP_SHA256_OFFSET     12u
#define OTP_SHA256_SIZE       32u
#define OTP_RESERVED_OFFSET   44u
#define OTP_RESERVED_SIZE     8u

/* ── I/O chunk size ─────────────────────────────────────────────────────── */
#define OTP_CHUNK_SIZE        (8u * 1024u)   /* 8 KB per I/O chunk */

/* ── Return codes ───────────────────────────────────────────────────────── */
typedef enum {
    OTP_OK               =  0,
    OTP_ERR_BAD_PARAM    = -1,   /* NULL or invalid argument           */
    OTP_ERR_IO_INPUT     = -2,   /* Cannot read plaintext/ciphertext   */
    OTP_ERR_IO_KEY       = -3,   /* Cannot read key                    */
    OTP_ERR_IO_OUTPUT    = -4,   /* Cannot write output file           */
    OTP_ERR_KEY_SIZE     = -5,   /* Key too small for file             */
    OTP_ERR_KEY_LOCKED   = -6,   /* Key reuse detected                 */
    OTP_ERR_HASH         = -7,   /* SHA-256 computation failed         */
    OTP_ERR_MAGIC        = -8,   /* Bad magic bytes in .enc file       */
    OTP_ERR_CORRUPT      = -9,   /* Truncated or corrupted .enc file   */
    OTP_ERR_HASH_MISMATCH= -10,  /* Decrypted hash != stored hash      */
    OTP_ERR_CRYPTO       = -11   /* Key generation failure             */
} OtpStatus;

/* ── Progress callback ──────────────────────────────────────────────────── */
/*
 * Called periodically during encrypt/decrypt with:
 *   bytes_done  — bytes processed so far
 *   bytes_total — total bytes to process
 *   userdata    — caller-supplied context pointer
 */
typedef void (*OtpProgressFn)(uint64_t bytes_done,
                               uint64_t bytes_total,
                               void *userdata);

/* ── Encrypt ────────────────────────────────────────────────────────────── */
/*
 * otp_encrypt()
 *
 * Encrypts `input_path` using the key at `key_path`, writing the result
 * (with OTP header) to `output_path`.
 *
 * Before encryption:
 *   1. Validates that key is not locked (reuse prevention).
 *   2. Validates that key file is >= plaintext size.
 *   3. Computes SHA-256 of plaintext and embeds in header.
 *
 * After encryption:
 *   4. Locks the key (creates .lock sidecar).
 *
 * Parameters:
 *   input_path   — path to plaintext file
 *   output_path  — path for output .enc file (will be created/truncated)
 *   key_path     — path to binary key file
 *   progress_fn  — optional progress callback (may be NULL)
 *   userdata     — passed through to progress_fn
 *
 * Returns OTP_OK on success.
 */
OtpStatus otp_encrypt(const char *input_path,
                       const char *output_path,
                       const char *key_path,
                       OtpProgressFn progress_fn,
                       void *userdata);

/* ── Decrypt ────────────────────────────────────────────────────────────── */
/*
 * otp_decrypt()
 *
 * Decrypts an OTP-encrypted file.
 *
 * Steps:
 *   1. Reads and validates OTP header (magic, sizes).
 *   2. Validates key size >= ciphertext payload size.
 *   3. Streams XOR decryption.
 *   4. Computes SHA-256 of decrypted output and verifies against header.
 *
 * Parameters:
 *   input_path   — path to .enc file
 *   key_path     — path to binary key file
 *   output_path  — path for decrypted output (will be created/truncated)
 *   progress_fn  — optional progress callback (may be NULL)
 *   userdata     — passed through to progress_fn
 *
 * Returns OTP_OK on success, OTP_ERR_HASH_MISMATCH if integrity fails.
 */
OtpStatus otp_decrypt(const char *input_path,
                       const char *key_path,
                       const char *output_path,
                       OtpProgressFn progress_fn,
                       void *userdata);

/* ── Key generation ─────────────────────────────────────────────────────── */
/*
 * otp_generate_key()
 *
 * Generates a new cryptographically secure key file of exactly `size` bytes
 * and saves it to `key_path`.  Ensures the keys/ directory exists.
 *
 * Parameters:
 *   key_path  — output path for the key
 *   size      — number of bytes to generate
 */
OtpStatus otp_generate_key(const char *key_path, uint64_t size);

/* ── Header I/O (exposed for testing) ──────────────────────────────────── */
typedef struct {
    uint8_t  magic[OTP_MAGIC_SIZE];          /* "OTP\x01"                  */
    uint64_t plaintext_size;                  /* Original file size         */
    uint8_t  sha256[OTP_SHA256_SIZE];         /* SHA-256 of plaintext       */
    uint8_t  reserved[OTP_RESERVED_SIZE];     /* Future use, zeroed         */
} OtpHeader;

/* Write header to fp at current position. Returns 0 on success. */
int otp_write_header(FILE *fp, const OtpHeader *hdr);

/* Read and validate header from fp at current position. Returns 0 on success.
 * Returns -1 on I/O error, -2 on bad magic bytes. */
int otp_read_header(FILE *fp, OtpHeader *hdr);

/* Return a human-readable string for an OtpStatus code */
const char *otp_status_str(OtpStatus s);

#ifdef __cplusplus
}
#endif

#endif /* OTP_H */
