/*
 * otp.c — One-Time Pad encryption/decryption engine
 *
 * Core algorithm: C[i] = P[i] XOR K[i]  (symmetric — decrypt = re-encrypt)
 *
 * Streaming design: all I/O is done in OTP_CHUNK_SIZE (8 KB) chunks.
 * The entire file is NEVER loaded into RAM.
 */

#include "otp.h"
#include "file_io.h"
#include "crypto_win.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── Endian helpers (OTP header is little-endian) ───────────────────────── */
static void write_u64_le(unsigned char *dst, uint64_t val)
{
    dst[0] = (unsigned char)(val       & 0xFF);
    dst[1] = (unsigned char)((val >> 8)  & 0xFF);
    dst[2] = (unsigned char)((val >> 16) & 0xFF);
    dst[3] = (unsigned char)((val >> 24) & 0xFF);
    dst[4] = (unsigned char)((val >> 32) & 0xFF);
    dst[5] = (unsigned char)((val >> 40) & 0xFF);
    dst[6] = (unsigned char)((val >> 48) & 0xFF);
    dst[7] = (unsigned char)((val >> 56) & 0xFF);
}

static uint64_t read_u64_le(const unsigned char *src)
{
    return (uint64_t)src[0]
         | ((uint64_t)src[1] << 8)
         | ((uint64_t)src[2] << 16)
         | ((uint64_t)src[3] << 24)
         | ((uint64_t)src[4] << 32)
         | ((uint64_t)src[5] << 40)
         | ((uint64_t)src[6] << 48)
         | ((uint64_t)src[7] << 56);
}

/* ── otp_status_str ─────────────────────────────────────────────────────── */
const char *otp_status_str(OtpStatus s)
{
    switch (s) {
        case OTP_OK:                return "OK";
        case OTP_ERR_BAD_PARAM:     return "Bad parameter (NULL argument)";
        case OTP_ERR_IO_INPUT:      return "Cannot read input file";
        case OTP_ERR_IO_KEY:        return "Cannot read key file";
        case OTP_ERR_IO_OUTPUT:     return "Cannot write output file";
        case OTP_ERR_KEY_SIZE:      return "Key too small for file";
        case OTP_ERR_KEY_LOCKED:    return "Key reuse detected (key is locked)";
        case OTP_ERR_HASH:          return "SHA-256 computation failed";
        case OTP_ERR_MAGIC:         return "Bad magic bytes — not an OTP file";
        case OTP_ERR_CORRUPT:       return "Truncated or corrupted .enc file";
        case OTP_ERR_HASH_MISMATCH: return "Integrity failure — SHA-256 mismatch";
        case OTP_ERR_CRYPTO:        return "Cryptographic key generation failed";
        default:                    return "Unknown error";
    }
}

/* ── otp_write_header ───────────────────────────────────────────────────── */
int otp_write_header(FILE *fp, const OtpHeader *hdr)
{
    /* Serialise to a fixed-layout byte array */
    unsigned char buf[OTP_HEADER_SIZE];
    memset(buf, 0, sizeof(buf));

    memcpy(buf + 0,  hdr->magic, OTP_MAGIC_SIZE);
    write_u64_le(buf + 4, hdr->plaintext_size);
    memcpy(buf + 12, hdr->sha256, OTP_SHA256_SIZE);
    memcpy(buf + 44, hdr->reserved, OTP_RESERVED_SIZE);

    if (fwrite(buf, 1, OTP_HEADER_SIZE, fp) != OTP_HEADER_SIZE) {
        return -1;
    }
    return 0;
}

/* ── otp_read_header ────────────────────────────────────────────────────── */
int otp_read_header(FILE *fp, OtpHeader *hdr)
{
    unsigned char buf[OTP_HEADER_SIZE];
    if (fread(buf, 1, OTP_HEADER_SIZE, fp) != OTP_HEADER_SIZE) {
        return -1;  /* I/O error or truncated file */
    }

    if (memcmp(buf, OTP_MAGIC, OTP_MAGIC_SIZE) != 0) {
        return -2;  /* Bad magic */
    }

    memcpy(hdr->magic, buf, OTP_MAGIC_SIZE);
    hdr->plaintext_size = read_u64_le(buf + 4);
    memcpy(hdr->sha256,   buf + 12, OTP_SHA256_SIZE);
    memcpy(hdr->reserved, buf + 44, OTP_RESERVED_SIZE);
    return 0;
}

/* ── otp_generate_key ───────────────────────────────────────────────────── */
OtpStatus otp_generate_key(const char *key_path, uint64_t size)
{
    if (!key_path || size == 0) return OTP_ERR_BAD_PARAM;

    CryptoStatus cs = crypto_gen_key_to_file(key_path, size);
    if (cs != CRYPTO_OK) {
        LOG_ERROR("Key generation failed: crypto error %d", cs);
        return OTP_ERR_CRYPTO;
    }

    LOG_SUCCESS("Key generated: %s (%llu bytes)", key_path, (unsigned long long)size);
    return OTP_OK;
}

/* ── otp_encrypt ────────────────────────────────────────────────────────── */
OtpStatus otp_encrypt(const char *input_path,
                       const char *output_path,
                       const char *key_path,
                       OtpProgressFn progress_fn,
                       void *userdata)
{
    if (!input_path || !output_path || !key_path) return OTP_ERR_BAD_PARAM;

    OtpStatus ret = OTP_OK;
    FILE *fp_in  = NULL;
    FILE *fp_key = NULL;
    FILE *fp_out = NULL;

    /* ── Pre-flight checks ──────────────────────────────────────────────── */

    /* Check if key is already locked (reuse prevention) */
    if (fio_key_is_locked(key_path)) {
        LOG_ERROR("Aborting: key '%s' has already been used.", key_path);
        LOG_WARN("SECURITY: OTP keys must NEVER be reused. Generate a new key.");
        return OTP_ERR_KEY_LOCKED;
    }

    /* Open input file */
    FioStatus fs = fio_open_read(input_path, &fp_in);
    if (fs != FIO_OK) return OTP_ERR_IO_INPUT;

    /* Get plaintext size */
    uint64_t plaintext_size = 0;
    fs = fio_get_size(fp_in, &plaintext_size);
    if (fs != FIO_OK || plaintext_size == 0) {
        LOG_ERROR("Input file is empty or unreadable: %s", input_path);
        ret = OTP_ERR_IO_INPUT;
        goto cleanup;
    }
    LOG_INFO("Input file: %s (%llu bytes)", input_path,
             (unsigned long long)plaintext_size);

    /* Validate key size */
    fs = fio_validate_key_size(key_path, plaintext_size);
    if (fs != FIO_OK) {
        ret = (fs == FIO_ERR_KEY_MISMATCH) ? OTP_ERR_KEY_SIZE : OTP_ERR_IO_KEY;
        goto cleanup;
    }

    /* ── Compute SHA-256 of plaintext ───────────────────────────────────── */
    LOG_INFO("Computing SHA-256 of plaintext...");
    unsigned char sha256[OTP_SHA256_SIZE];
    CryptoStatus cs = crypto_sha256_file(input_path, sha256);
    if (cs != CRYPTO_OK) {
        LOG_ERROR("SHA-256 computation failed for: %s", input_path);
        ret = OTP_ERR_HASH;
        goto cleanup;
    }
    {
        char hexbuf[OTP_SHA256_SIZE * 2 + 1];
        crypto_hex_string(sha256, OTP_SHA256_SIZE, hexbuf);
        LOG_INFO("Plaintext SHA-256: %s", hexbuf);
    }

    /* ── Open key and output files ──────────────────────────────────────── */
    fs = fio_open_read(key_path, &fp_key);
    if (fs != FIO_OK) { ret = OTP_ERR_IO_KEY; goto cleanup; }

    fs = fio_open_write(output_path, &fp_out);
    if (fs != FIO_OK) { ret = OTP_ERR_IO_OUTPUT; goto cleanup; }

    /* ── Lock the key NOW (before writing any output) ───────────────────── */
    /* This ensures that even if we crash mid-encryption, the key is marked. */
    fs = fio_key_lock(key_path);
    if (fs != FIO_OK) {
        ret = OTP_ERR_KEY_LOCKED;
        goto cleanup;
    }

    /* ── Write OTP header ───────────────────────────────────────────────── */
    OtpHeader hdr;
    memcpy(hdr.magic, OTP_MAGIC, OTP_MAGIC_SIZE);
    hdr.plaintext_size = plaintext_size;
    memcpy(hdr.sha256, sha256, OTP_SHA256_SIZE);
    memset(hdr.reserved, 0, OTP_RESERVED_SIZE);

    if (otp_write_header(fp_out, &hdr) != 0) {
        LOG_ERROR("Failed to write OTP header to: %s", output_path);
        ret = OTP_ERR_IO_OUTPUT;
        fio_key_unlock(key_path);   /* Rollback lock on failure */
        goto cleanup;
    }

    /* ── Stream XOR encryption ──────────────────────────────────────────── */
    LOG_INFO("Encrypting...");
    unsigned char pt_buf[OTP_CHUNK_SIZE];   /* plaintext chunk  */
    unsigned char ky_buf[OTP_CHUNK_SIZE];   /* key chunk        */
    unsigned char ct_buf[OTP_CHUNK_SIZE];   /* ciphertext chunk */

    uint64_t processed = 0;
    uint64_t remaining = plaintext_size;

    while (remaining > 0) {
        size_t this_chunk = (remaining > OTP_CHUNK_SIZE)
                            ? OTP_CHUNK_SIZE : (size_t)remaining;

        /* Read plaintext chunk */
        size_t n_pt = fread(pt_buf, 1, this_chunk, fp_in);
        if (n_pt != this_chunk) {
            LOG_ERROR("Unexpected end of input file at offset %llu",
                      (unsigned long long)processed);
            ret = OTP_ERR_IO_INPUT;
            fio_key_unlock(key_path);
            goto cleanup;
        }

        /* Read key chunk */
        size_t n_ky = fread(ky_buf, 1, this_chunk, fp_key);
        if (n_ky != this_chunk) {
            LOG_ERROR("Unexpected end of key file at offset %llu",
                      (unsigned long long)processed);
            ret = OTP_ERR_IO_KEY;
            fio_key_unlock(key_path);
            goto cleanup;
        }

        /* XOR: C[i] = P[i] XOR K[i] */
        for (size_t i = 0; i < this_chunk; i++) {
            ct_buf[i] = pt_buf[i] ^ ky_buf[i];
        }

        /* Write ciphertext chunk */
        if (fwrite(ct_buf, 1, this_chunk, fp_out) != this_chunk) {
            LOG_ERROR("Write failure at offset %llu",
                      (unsigned long long)(OTP_HEADER_SIZE + processed));
            ret = OTP_ERR_IO_OUTPUT;
            fio_key_unlock(key_path);
            goto cleanup;
        }

        processed += this_chunk;
        remaining -= this_chunk;

        if (progress_fn) {
            progress_fn(processed, plaintext_size, userdata);
        }
    }

    /* Securely zero sensitive buffers */
    crypto_secure_zero(pt_buf, sizeof(pt_buf));
    crypto_secure_zero(ky_buf, sizeof(ky_buf));
    crypto_secure_zero(ct_buf, sizeof(ct_buf));

    LOG_SUCCESS("Encryption complete: %s (%llu bytes encrypted)",
                output_path, (unsigned long long)processed);

cleanup:
    if (fp_in)  fclose(fp_in);
    if (fp_key) fclose(fp_key);
    if (fp_out) fclose(fp_out);
    return ret;
}

/* ── otp_decrypt ────────────────────────────────────────────────────────── */
OtpStatus otp_decrypt(const char *input_path,
                       const char *key_path,
                       const char *output_path,
                       OtpProgressFn progress_fn,
                       void *userdata)
{
    if (!input_path || !key_path || !output_path) return OTP_ERR_BAD_PARAM;

    OtpStatus ret = OTP_OK;
    FILE *fp_in  = NULL;
    FILE *fp_key = NULL;
    FILE *fp_out = NULL;

    unsigned char ct_buf[OTP_CHUNK_SIZE];
    unsigned char ky_buf[OTP_CHUNK_SIZE];
    unsigned char pt_buf[OTP_CHUNK_SIZE];

    /* ── Open encrypted input ───────────────────────────────────────────── */
    FioStatus fs = fio_open_read(input_path, &fp_in);
    if (fs != FIO_OK) return OTP_ERR_IO_INPUT;

    /* Validate minimum file size */
    uint64_t enc_file_size = 0;
    fs = fio_get_size(fp_in, &enc_file_size);
    if (fs != FIO_OK || enc_file_size < OTP_HEADER_SIZE) {
        LOG_ERROR("Encrypted file too small to contain a valid header: %s", input_path);
        ret = OTP_ERR_CORRUPT;
        goto cleanup;
    }

    /* ── Read and validate OTP header ───────────────────────────────────── */
    OtpHeader hdr;
    int hr = otp_read_header(fp_in, &hdr);
    if (hr == -1) {
        LOG_ERROR("Failed to read OTP header from: %s", input_path);
        ret = OTP_ERR_CORRUPT;
        goto cleanup;
    }
    if (hr == -2) {
        LOG_ERROR("Bad magic bytes — '%s' is not an OTP-encrypted file", input_path);
        ret = OTP_ERR_MAGIC;
        goto cleanup;
    }

    uint64_t plaintext_size = hdr.plaintext_size;
    uint64_t expected_enc_size = OTP_HEADER_SIZE + plaintext_size;

    if (enc_file_size != expected_enc_size) {
        LOG_ERROR("Encrypted file size mismatch: expected %llu bytes, got %llu bytes",
                  (unsigned long long)expected_enc_size,
                  (unsigned long long)enc_file_size);
        ret = OTP_ERR_CORRUPT;
        goto cleanup;
    }

    LOG_INFO("OTP header valid. Plaintext size: %llu bytes", (unsigned long long)plaintext_size);
    {
        char hexbuf[OTP_SHA256_SIZE * 2 + 1];
        crypto_hex_string(hdr.sha256, OTP_SHA256_SIZE, hexbuf);
        LOG_INFO("Expected SHA-256: %s", hexbuf);
    }

    /* ── Validate key size ──────────────────────────────────────────────── */
    fs = fio_validate_key_size(key_path, plaintext_size);
    if (fs != FIO_OK) {
        ret = (fs == FIO_ERR_KEY_MISMATCH) ? OTP_ERR_KEY_SIZE : OTP_ERR_IO_KEY;
        goto cleanup;
    }

    /* ── Open key and output ─────────────────────────────────────────────── */
    fs = fio_open_read(key_path, &fp_key);
    if (fs != FIO_OK) { ret = OTP_ERR_IO_KEY; goto cleanup; }

    fs = fio_open_write(output_path, &fp_out);
    if (fs != FIO_OK) { ret = OTP_ERR_IO_OUTPUT; goto cleanup; }

    /* ── Stream XOR decryption ──────────────────────────────────────────── */
    LOG_INFO("Decrypting...");

    uint64_t processed = 0;
    uint64_t remaining = plaintext_size;

    while (remaining > 0) {
        size_t this_chunk = (remaining > OTP_CHUNK_SIZE)
                            ? OTP_CHUNK_SIZE : (size_t)remaining;

        size_t n_ct = fread(ct_buf, 1, this_chunk, fp_in);
        if (n_ct != this_chunk) {
            LOG_ERROR("Unexpected end of ciphertext at offset %llu",
                      (unsigned long long)processed);
            ret = OTP_ERR_IO_INPUT;
            goto cleanup;
        }

        size_t n_ky = fread(ky_buf, 1, this_chunk, fp_key);
        if (n_ky != this_chunk) {
            LOG_ERROR("Unexpected end of key at offset %llu",
                      (unsigned long long)processed);
            ret = OTP_ERR_IO_KEY;
            goto cleanup;
        }

        /* XOR: P[i] = C[i] XOR K[i]  (same operation as encrypt) */
        for (size_t i = 0; i < this_chunk; i++) {
            pt_buf[i] = ct_buf[i] ^ ky_buf[i];
        }

        if (fwrite(pt_buf, 1, this_chunk, fp_out) != this_chunk) {
            LOG_ERROR("Write failure at offset %llu", (unsigned long long)processed);
            ret = OTP_ERR_IO_OUTPUT;
            goto cleanup;
        }

        processed += this_chunk;
        remaining -= this_chunk;

        if (progress_fn) {
            progress_fn(processed, plaintext_size, userdata);
        }
    }

    /* Securely zero sensitive buffers */
    crypto_secure_zero(ct_buf, sizeof(ct_buf));
    crypto_secure_zero(ky_buf, sizeof(ky_buf));
    crypto_secure_zero(pt_buf, sizeof(pt_buf));

    /* Close output before computing its SHA-256 */
    fclose(fp_out);
    fp_out = NULL;

    /* ── Verify integrity: SHA-256 of decrypted output ───────────────────── */
    LOG_INFO("Verifying SHA-256 integrity...");
    unsigned char computed_sha[OTP_SHA256_SIZE];
    CryptoStatus cs = crypto_sha256_file(output_path, computed_sha);
    if (cs != CRYPTO_OK) {
        LOG_ERROR("SHA-256 computation failed on decrypted output");
        ret = OTP_ERR_HASH;
        goto cleanup;
    }

    if (memcmp(computed_sha, hdr.sha256, OTP_SHA256_SIZE) != 0) {
        char got[OTP_SHA256_SIZE * 2 + 1];
        char exp[OTP_SHA256_SIZE * 2 + 1];
        crypto_hex_string(computed_sha, OTP_SHA256_SIZE, got);
        crypto_hex_string(hdr.sha256,   OTP_SHA256_SIZE, exp);
        LOG_ERROR("INTEGRITY FAILURE: SHA-256 mismatch!");
        LOG_ERROR("  Expected: %s", exp);
        LOG_ERROR("  Got:      %s", got);
        ret = OTP_ERR_HASH_MISMATCH;
        goto cleanup;
    }

    {
        char hexbuf[OTP_SHA256_SIZE * 2 + 1];
        crypto_hex_string(computed_sha, OTP_SHA256_SIZE, hexbuf);
        LOG_SUCCESS("Integrity verified: SHA-256 %s", hexbuf);
    }
    LOG_SUCCESS("Decryption complete: %s (%llu bytes)",
                output_path, (unsigned long long)processed);

cleanup:
    crypto_secure_zero(ct_buf, sizeof(ct_buf));
    crypto_secure_zero(ky_buf, sizeof(ky_buf));
    crypto_secure_zero(pt_buf, sizeof(pt_buf));
    if (fp_in)  fclose(fp_in);
    if (fp_key) fclose(fp_key);
    if (fp_out) fclose(fp_out);
    return ret;
}
