/*
 * test_crypto.c — Unit tests for Windows CNG cryptographic primitives
 *
 * Covers:
 *   - SHA-256 against a NIST known-answer test vector (KAT)
 *   - crypto_hex_string correctness
 *   - crypto_fill_buffer returns data (non-trivial CSPRNG output)
 *   - crypto_secure_zero actually zeroes memory
 *   - SHA-256 buffer vs file consistency
 *
 * NIST vector source:
 *   https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
 *   SHA-256("abc") =
 *   ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469324190a435b7831c
 *   (FIPS 180-4, Example 1)
 */

#include "test_runner.h"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../src/crypto_win.h"

/* ── NIST SHA-256 KAT vector ─────────────────────────────────────────────── */
static const unsigned char KAT_INPUT[]  = "abc";
static const size_t        KAT_LEN      = 3;
static const unsigned char KAT_DIGEST[] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x2e, 0xc7,
    0x3b, 0x00, 0x36, 0x1b, 0xbe, 0xf0, 0x46, 0x93,
    0x24, 0x19, 0x0a, 0x43, 0x5b, 0x78, 0x31, 0xc0
};
static const char KAT_HEX[] =
    "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469324190a435b7831c0";

/* ── Tests ───────────────────────────────────────────────────────────────── */

static void test_sha256_nist_kat_buffer(void)
{
    unsigned char digest[SHA256_DIGEST_BYTES];
    CryptoStatus s = crypto_sha256_buffer(KAT_INPUT, KAT_LEN, digest);

    TEST_ASSERT_EQ_INT(CRYPTO_OK, s,
                       "crypto_sha256_buffer returns CRYPTO_OK for \"abc\"");
    TEST_ASSERT_MEM_EQ(KAT_DIGEST, digest, SHA256_DIGEST_BYTES,
                       "SHA-256(\"abc\") matches NIST KAT vector (FIPS 180-4)");
}

static void test_sha256_nist_kat_file(void)
{
    /* Write "abc" to a temp file and hash it */
    const char *tmp = "tests\\tmp_sha256_kat.bin";
    FILE *fp = fopen(tmp, "wb");
    if (!fp) {
        fprintf(stderr, "[SKIP] Cannot create temp file for SHA-256 file test\n");
        return;
    }
    fwrite(KAT_INPUT, 1, KAT_LEN, fp);
    fclose(fp);

    unsigned char digest[SHA256_DIGEST_BYTES];
    CryptoStatus s = crypto_sha256_file(tmp, digest);
    remove(tmp);

    TEST_ASSERT_EQ_INT(CRYPTO_OK, s,
                       "crypto_sha256_file returns CRYPTO_OK");
    TEST_ASSERT_MEM_EQ(KAT_DIGEST, digest, SHA256_DIGEST_BYTES,
                       "SHA-256 file hash matches buffer hash for same data");
}

static void test_sha256_empty_input(void)
{
    /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    static const unsigned char EMPTY_DIGEST[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    unsigned char digest[SHA256_DIGEST_BYTES];
    CryptoStatus s = crypto_sha256_buffer((const unsigned char *)"", 0, digest);

    TEST_ASSERT_EQ_INT(CRYPTO_OK, s, "SHA-256 of empty input: CRYPTO_OK");
    TEST_ASSERT_MEM_EQ(EMPTY_DIGEST, digest, SHA256_DIGEST_BYTES,
                       "SHA-256(\"\") matches NIST KAT");
}

static void test_hex_string_correctness(void)
{
    /* Single byte: 0xAB → "ab" */
    const unsigned char byte = 0xAB;
    char hex[3];
    crypto_hex_string(&byte, 1, hex);
    TEST_ASSERT(strcmp(hex, "ab") == 0,
                "hex(0xAB) == \"ab\" (lowercase)");

    /* Full KAT digest encodes correctly */
    char kat_hex[SHA256_DIGEST_BYTES * 2 + 1];
    crypto_hex_string(KAT_DIGEST, SHA256_DIGEST_BYTES, kat_hex);
    /* Compare first 63 chars (KAT_HEX above has 65 bytes total with null) */
    TEST_ASSERT(strncmp(kat_hex, KAT_HEX, SHA256_DIGEST_BYTES * 2) == 0,
                "KAT digest encodes to correct hex string");
}

static void test_fill_buffer_produces_output(void)
{
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    CryptoStatus s = crypto_fill_buffer(buf, sizeof(buf));
    TEST_ASSERT_EQ_INT(CRYPTO_OK, s, "crypto_fill_buffer returns CRYPTO_OK");

    /* Verify the buffer is not all zeros (probability of all-zero from CSPRNG
     * is 1/2^512 — effectively impossible) */
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) { all_zero = 0; break; }
    }
    TEST_ASSERT(!all_zero,
                "CSPRNG output is not all-zero (randomness sanity check)");

    crypto_secure_zero(buf, sizeof(buf));
}

static void test_secure_zero_erases_data(void)
{
    unsigned char buf[32];
    memset(buf, 0xFF, sizeof(buf));

    crypto_secure_zero(buf, sizeof(buf));

    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) { all_zero = 0; break; }
    }
    TEST_ASSERT(all_zero, "crypto_secure_zero fills buffer with 0x00");
}

static void test_null_args_rejected(void)
{
    unsigned char digest[SHA256_DIGEST_BYTES];
    unsigned char buf[8];

    TEST_ASSERT_EQ_INT(CRYPTO_ERR_BAD_PARAM,
                       crypto_sha256_buffer(NULL, 8, digest),
                       "NULL data → CRYPTO_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(CRYPTO_ERR_BAD_PARAM,
                       crypto_sha256_buffer(buf, 8, NULL),
                       "NULL digest out → CRYPTO_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(CRYPTO_ERR_BAD_PARAM,
                       crypto_sha256_file(NULL, digest),
                       "NULL path → CRYPTO_ERR_BAD_PARAM");
    TEST_ASSERT_EQ_INT(CRYPTO_ERR_BAD_PARAM,
                       crypto_fill_buffer(NULL, 8),
                       "NULL buffer → CRYPTO_ERR_BAD_PARAM");
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void)
{
    printf("Cryptographic Primitive Tests\n");
    printf("==============================\n");

    RUN_TEST(test_sha256_nist_kat_buffer);
    RUN_TEST(test_sha256_nist_kat_file);
    RUN_TEST(test_sha256_empty_input);
    RUN_TEST(test_hex_string_correctness);
    RUN_TEST(test_fill_buffer_produces_output);
    RUN_TEST(test_secure_zero_erases_data);
    RUN_TEST(test_null_args_rejected);

    return TEST_SUMMARY();
}
