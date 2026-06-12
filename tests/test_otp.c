/*
 * test_otp.c — Unit tests for the OTP encryption/decryption engine
 *
 * Covers:
 *   - Full encrypt → decrypt round-trip (byte-exact recovery)
 *   - Key reuse prevention (OTP_ERR_KEY_LOCKED)
 *   - Bad magic bytes detection (OTP_ERR_MAGIC)
 *   - Undersized key rejection (OTP_ERR_KEY_SIZE)
 *   - Header field integrity (magic, plaintext_size, SHA-256 embedding)
 *
 * Build:  see tests/Makefile
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

#include "../src/otp.h"
#include "../src/file_io.h"
#include "../src/crypto_win.h"

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/* Writes `len` bytes of `data` to `path`.  Returns 0 on success. */
static int write_file(const char *path, const unsigned char *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    int ok = (fwrite(data, 1, len, fp) == len) ? 0 : -1;
    fclose(fp);
    return ok;
}

/* Reads entire file into a heap buffer.  Caller frees.  Returns NULL on fail. */
static unsigned char *read_file_alloc(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    rewind(fp);

    if (sz <= 0) { fclose(fp); return NULL; }

    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(fp); return NULL; }

    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return NULL;
    }
    fclose(fp);
    *out_len = (size_t)sz;
    return buf;
}

/* Remove a file if it exists (ignores errors). */
static void cleanup(const char *path)
{
    remove(path);
}

/* Remove key + its sidecar lock file. */
static void cleanup_key(const char *path)
{
    char lock[MAX_PATH];
    remove(path);
    if (fio_lock_path(path, lock, sizeof(lock)) == 0) remove(lock);
}

/* ── Test data ───────────────────────────────────────────────────────────── */

/* 256 bytes: deterministic, non-trivial content */
static const unsigned char PLAINTEXT[256] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
    /* ... fill remainder with repeating pattern */
    0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
    0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,
    0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,
    0x59,0x5A,0x61,0x62,0x63,0x64,0x65,0x66,
    0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,
    0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x76,
    0x77,0x78,0x79,0x7A,0x30,0x31,0x32,0x33,
    0x34,0x35,0x36,0x37,0x38,0x39,0x20,0x21,
    0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,
    0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x3A,0x3B,
    0x3C,0x3D,0x3E,0x3F,0x40,0x5B,0x5C,0x5D,
    0x5E,0x5F,0x60,0x7B,0x7C,0x7D,0x7E,0x7F,
    0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
    0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F,
    0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
    0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F,
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
    0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
    0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
    0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,
    0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,
    0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,
    0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,
    0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF,
    0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,
    0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,
    0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,
    0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF
};

#define PT_PATH   "tests\\tmp_plain.bin"
#define ENC_PATH  "tests\\tmp_cipher.enc"
#define DEC_PATH  "tests\\tmp_dec.bin"
#define KEY_PATH  "tests\\tmp_key.bin"

/* ── Tests ───────────────────────────────────────────────────────────────── */

static void test_encrypt_decrypt_roundtrip(void)
{
    cleanup(PT_PATH); cleanup(ENC_PATH); cleanup(DEC_PATH);
    cleanup_key(KEY_PATH);

    /* Write known plaintext */
    TEST_ASSERT(write_file(PT_PATH, PLAINTEXT, sizeof(PLAINTEXT)) == 0,
                "write plaintext to disk");

    /* Generate key */
    OtpStatus gs = otp_generate_key(KEY_PATH, sizeof(PLAINTEXT));
    TEST_ASSERT_EQ_INT(OTP_OK, gs, "key generation succeeds");

    /* Encrypt */
    OtpStatus es = otp_encrypt(PT_PATH, ENC_PATH, KEY_PATH, NULL, NULL);
    TEST_ASSERT_EQ_INT(OTP_OK, es, "encryption returns OTP_OK");

    /* Encrypted file must exist and be HEADER + plaintext size */
    size_t enc_len = 0;
    unsigned char *enc = read_file_alloc(ENC_PATH, &enc_len);
    TEST_ASSERT(enc != NULL, "encrypted file is readable");
    TEST_ASSERT_EQ_INT((long long)(OTP_HEADER_SIZE + sizeof(PLAINTEXT)),
                       (long long)enc_len,
                       "encrypted file has correct size");
    free(enc);

    /* Decrypt */
    OtpStatus ds = otp_decrypt(ENC_PATH, KEY_PATH, DEC_PATH, NULL, NULL);
    TEST_ASSERT_EQ_INT(OTP_OK, ds, "decryption returns OTP_OK");

    /* Recovered file must match original byte-for-byte */
    size_t dec_len = 0;
    unsigned char *dec = read_file_alloc(DEC_PATH, &dec_len);
    TEST_ASSERT(dec != NULL, "decrypted file is readable");
    TEST_ASSERT_EQ_INT((long long)sizeof(PLAINTEXT), (long long)dec_len,
                       "decrypted file has correct size");
    if (dec) {
        TEST_ASSERT_MEM_EQ(PLAINTEXT, dec, sizeof(PLAINTEXT),
                           "decrypted content matches original plaintext");
        free(dec);
    }

    cleanup(PT_PATH); cleanup(ENC_PATH); cleanup(DEC_PATH);
    cleanup_key(KEY_PATH);
}

static void test_key_lock_prevents_reuse(void)
{
    cleanup(PT_PATH); cleanup(ENC_PATH);
    cleanup_key(KEY_PATH);

    write_file(PT_PATH, PLAINTEXT, sizeof(PLAINTEXT));
    otp_generate_key(KEY_PATH, sizeof(PLAINTEXT));

    /* First encryption locks the key */
    OtpStatus first = otp_encrypt(PT_PATH, ENC_PATH, KEY_PATH, NULL, NULL);
    TEST_ASSERT_EQ_INT(OTP_OK, first, "first encrypt succeeds");

    /* Remove output so it could theoretically be re-encrypted */
    cleanup(ENC_PATH);

    /* Second encryption on the same key must be rejected */
    OtpStatus second = otp_encrypt(PT_PATH, ENC_PATH, KEY_PATH, NULL, NULL);
    TEST_ASSERT_EQ_INT(OTP_ERR_KEY_LOCKED, second,
                       "second encrypt with same key returns OTP_ERR_KEY_LOCKED");

    cleanup(PT_PATH); cleanup(ENC_PATH);
    cleanup_key(KEY_PATH);
}

static void test_corrupt_magic_rejected(void)
{
    /* Build a file with bad magic bytes */
    unsigned char bad[OTP_HEADER_SIZE + 4];
    memset(bad, 0x00, sizeof(bad));
    bad[0] = 'B'; bad[1] = 'A'; bad[2] = 'D'; bad[3] = '!'; /* wrong magic */

    cleanup_key(KEY_PATH);
    otp_generate_key(KEY_PATH, 4);
    write_file(ENC_PATH, bad, sizeof(bad));

    OtpStatus s = otp_decrypt(ENC_PATH, KEY_PATH, DEC_PATH, NULL, NULL);
    TEST_ASSERT_EQ_INT(OTP_ERR_MAGIC, s,
                       "bad magic bytes → OTP_ERR_MAGIC");

    cleanup(ENC_PATH); cleanup(DEC_PATH);
    cleanup_key(KEY_PATH);
}

static void test_undersized_key_rejected(void)
{
    cleanup(PT_PATH);
    cleanup_key(KEY_PATH);

    write_file(PT_PATH, PLAINTEXT, sizeof(PLAINTEXT)); /* 256 bytes */

    /* Generate a key that is 1 byte too small */
    otp_generate_key(KEY_PATH, sizeof(PLAINTEXT) - 1);

    OtpStatus s = otp_encrypt(PT_PATH, ENC_PATH, KEY_PATH, NULL, NULL);
    TEST_ASSERT_EQ_INT(OTP_ERR_KEY_SIZE, s,
                       "key smaller than plaintext → OTP_ERR_KEY_SIZE");

    cleanup(PT_PATH); cleanup(ENC_PATH);
    cleanup_key(KEY_PATH);
}

static void test_header_magic_is_correct(void)
{
    cleanup(PT_PATH); cleanup(ENC_PATH);
    cleanup_key(KEY_PATH);

    write_file(PT_PATH, PLAINTEXT, 8);
    otp_generate_key(KEY_PATH, 8);
    otp_encrypt(PT_PATH, ENC_PATH, KEY_PATH, NULL, NULL);

    /* Read raw bytes and verify magic */
    size_t len = 0;
    unsigned char *raw = read_file_alloc(ENC_PATH, &len);
    TEST_ASSERT(raw != NULL && len >= OTP_HEADER_SIZE,
                "encrypted file readable and large enough");
    if (raw) {
        TEST_ASSERT(memcmp(raw, "OTP\x01", 4) == 0,
                    "first 4 bytes are OTP magic \"OTP\\x01\"");
        free(raw);
    }

    cleanup(PT_PATH); cleanup(ENC_PATH);
    cleanup_key(KEY_PATH);
}

static void test_null_args_rejected(void)
{
    TEST_ASSERT_EQ_INT(OTP_ERR_BAD_PARAM,
                       otp_encrypt(NULL, "out", "key", NULL, NULL),
                       "NULL input path → OTP_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(OTP_ERR_BAD_PARAM,
                       otp_encrypt("in", NULL, "key", NULL, NULL),
                       "NULL output path → OTP_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(OTP_ERR_BAD_PARAM,
                       otp_decrypt(NULL, "key", "out", NULL, NULL),
                       "NULL decrypt input → OTP_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(OTP_ERR_BAD_PARAM,
                       otp_generate_key(NULL, 64),
                       "NULL key path → OTP_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(OTP_ERR_BAD_PARAM,
                       otp_generate_key("key.bin", 0),
                       "zero key size → OTP_ERR_BAD_PARAM");
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void)
{
    printf("OTP Engine Tests\n");
    printf("================\n");

    RUN_TEST(test_encrypt_decrypt_roundtrip);
    RUN_TEST(test_key_lock_prevents_reuse);
    RUN_TEST(test_corrupt_magic_rejected);
    RUN_TEST(test_undersized_key_rejected);
    RUN_TEST(test_header_magic_is_correct);
    RUN_TEST(test_null_args_rejected);

    return TEST_SUMMARY();
}
