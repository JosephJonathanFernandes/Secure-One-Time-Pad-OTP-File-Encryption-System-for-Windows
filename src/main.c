/*
 * main.c — OTP Encryption Tool: CLI entry point and argument dispatcher
 *
 * Usage:
 *   otp.exe -e <input> <output.enc> <key.bin>   Encrypt
 *   otp.exe -d <input.enc> <key.bin> <output>   Decrypt
 *   otp.exe -g <size_bytes> <key.bin>            Generate key
 *   otp.exe --batch -e <in_dir> <out_dir> <key_dir>  Batch encrypt
 *   otp.exe --verify <file> <sha256_hex>         Verify file hash
 *
 * Flags:
 *   -v, --verbose         Enable verbose/debug output
 *   --self-destruct-key   Securely delete key after successful decryption
 *   --no-lock             Skip key locking (DANGEROUS — experts only)
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "otp.h"
#include "file_io.h"
#include "crypto_win.h"
#include "logger.h"

/* ── Version ────────────────────────────────────────────────────────────── */
#define OTP_VERSION_MAJOR  1
#define OTP_VERSION_MINOR  0
#define OTP_VERSION_PATCH  0
#define OTP_VERSION_STR    "1.0.0"

/* ── CLI Option flags ────────────────────────────────────────────────────── */
typedef struct {
    int         verbose;           /* -v / --verbose                  */
    int         self_destruct;     /* --self-destruct-key             */
    int         batch_mode;        /* --batch                         */
    int         show_version;      /* --version                       */
    int         show_help;         /* --help / -h                     */
    int         verify_only;       /* --verify                        */
    int         selftest;          /* --selftest                      */
    const char *mode;              /* "-e", "-d", "-g", "--verify"    */
    /* Positional arguments (after flags) */
    const char *args[8];
    int         arg_count;
} CliOptions;

/* ── Progress callback (bridges to logger) ───────────────────────────────── */
static void progress_callback(uint64_t done, uint64_t total, void *userdata)
{
    const char *label = (const char *)userdata;
    if (!label) label = "Processing";
    log_progress(done, total, label);
}

/* ── Banner ─────────────────────────────────────────────────────────────── */
static void print_banner(void)
{
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║   OTP File Encryption Tool  v%-17s║\n", OTP_VERSION_STR);
    printf("  ║   One-Time Pad | BCrypt | SHA-256            ║\n");
    printf("  ║   Windows CNG  | Production Grade            ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n");
    printf("\n");
}

/* ── Help text ──────────────────────────────────────────────────────────── */
static void print_help(void)
{
    print_banner();
    printf("USAGE:\n");
    printf("  otp.exe -e <input>       <output.enc> <key.bin>   Encrypt a file\n");
    printf("  otp.exe -d <input.enc>   <key.bin>   <output>     Decrypt a file\n");
    printf("  otp.exe -g <size_bytes>  <key.bin>                Generate key\n");
    printf("  otp.exe --batch -e <in_dir> <out_dir> <key_dir>   Batch encrypt dir\n");
    printf("  otp.exe --verify <file>  <sha256_hex>             Verify file hash\n");
    printf("  otp.exe --selftest                                Run internal self-test\n");
    printf("\n");
    printf("FLAGS:\n");
    printf("  -v, --verbose           Verbose/debug output\n");
    printf("  --self-destruct-key     Delete key securely after decrypt\n");
    printf("  --version               Print version and exit\n");
    printf("  -h, --help              Print this help\n");
    printf("  --selftest              Run internal cryptographic self-test\n");
    printf("\n");
    printf("EXAMPLES:\n");
    printf("  otp.exe --selftest\n");
    printf("  otp.exe -g 1048576 keys\\myfile.key\n");
    printf("  otp.exe -e input_files\\secret.txt output_files\\secret.enc keys\\myfile.key\n");
    printf("  otp.exe -d output_files\\secret.enc keys\\myfile.key output_files\\recovered.txt\n");
    printf("  otp.exe -d secret.enc secret.key out.txt --self-destruct-key\n");
    printf("\n");
    printf("NOTES:\n");
    printf("  * Key size must exactly equal or exceed the plaintext file size.\n");
    printf("  * Keys are locked after use to prevent reuse. Generate a new key each time.\n");
    printf("  * --self-destruct-key performs a 3-pass overwrite before deletion.\n");
    printf("  * SHA-256 integrity is verified automatically on every decryption.\n");
    printf("\n");
}

/* ── Argument parser ─────────────────────────────────────────────────────── */
static CliOptions parse_args(int argc, char *argv[])
{
    CliOptions opts;
    memset(&opts, 0, sizeof(opts));

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
            opts.verbose = 1;
        } else if (strcmp(arg, "--self-destruct-key") == 0) {
            opts.self_destruct = 1;
        } else if (strcmp(arg, "--batch") == 0) {
            opts.batch_mode = 1;
        } else if (strcmp(arg, "--version") == 0) {
            opts.show_version = 1;
        } else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            opts.show_help = 1;
        } else if (strcmp(arg, "--selftest") == 0) {
            opts.selftest = 1;
        } else if (strcmp(arg, "-e") == 0 || strcmp(arg, "-d") == 0 ||
                   strcmp(arg, "-g") == 0 || strcmp(arg, "--verify") == 0) {
            opts.mode = arg;
        } else {
            /* Positional argument */
            if (opts.arg_count < 8) {
                opts.args[opts.arg_count++] = arg;
            }
        }
    }

    return opts;
}

/* ── Mode: Encrypt ───────────────────────────────────────────────────────── */
static int do_encrypt(const CliOptions *opts)
{
    if (opts->arg_count < 3) {
        LOG_ERROR("Encrypt mode requires 3 arguments: <input> <output.enc> <key.bin>");
        return 1;
    }

    const char *input    = opts->args[0];
    const char *output   = opts->args[1];
    const char *key_path = opts->args[2];

    LOG_INFO("Mode:    ENCRYPT");
    LOG_INFO("Input:   %s", input);
    LOG_INFO("Output:  %s", output);
    LOG_INFO("Key:     %s", key_path);
    printf("\n");

    /* Ensure output directory exists */
    {
        char out_dir[MAX_PATH];
        strncpy(out_dir, output, sizeof(out_dir) - 1);
        out_dir[sizeof(out_dir) - 1] = '\0';
        /* Strip filename from path */
        char *last_sep = strrchr(out_dir, '\\');
        if (!last_sep) last_sep = strrchr(out_dir, '/');
        if (last_sep) {
            *last_sep = '\0';
            fio_ensure_dir(out_dir);
        }
    }

    OtpStatus s = otp_encrypt(input, output, key_path,
                               progress_callback, (void *)"Encrypting");
    log_progress_done();

    if (s != OTP_OK) {
        LOG_ERROR("Encryption failed: %s", otp_status_str(s));
        return 1;
    }
    return 0;
}

/* ── Mode: Decrypt ───────────────────────────────────────────────────────── */
static int do_decrypt(const CliOptions *opts)
{
    if (opts->arg_count < 3) {
        LOG_ERROR("Decrypt mode requires 3 arguments: <input.enc> <key.bin> <output>");
        return 1;
    }

    const char *input    = opts->args[0];
    const char *key_path = opts->args[1];
    const char *output   = opts->args[2];

    LOG_INFO("Mode:    DECRYPT");
    LOG_INFO("Input:   %s", input);
    LOG_INFO("Key:     %s", key_path);
    LOG_INFO("Output:  %s", output);
    if (opts->self_destruct) {
        LOG_WARN("--self-destruct-key is enabled: key will be securely deleted on success");
    }
    printf("\n");

    OtpStatus s = otp_decrypt(input, key_path, output,
                               progress_callback, (void *)"Decrypting");
    log_progress_done();

    if (s != OTP_OK) {
        LOG_ERROR("Decryption failed: %s", otp_status_str(s));
        return 1;
    }

    /* Self-destruct key if requested */
    if (opts->self_destruct) {
        LOG_INFO("Performing secure key deletion...");
        FioStatus fs = fio_secure_delete(key_path);
        if (fs != FIO_OK) {
            LOG_WARN("Could not securely delete key file: %s", key_path);
        }
        /* Also delete the lock file */
        char lock_path[MAX_PATH];
        if (fio_lock_path(key_path, lock_path, sizeof(lock_path)) == 0) {
            fio_secure_delete(lock_path);
        }
    }

    return 0;
}

/* ── Mode: Generate Key ──────────────────────────────────────────────────── */
static int do_generate(const CliOptions *opts)
{
    if (opts->arg_count < 2) {
        LOG_ERROR("Generate mode requires 2 arguments: <size_bytes> <key.bin>");
        return 1;
    }

    const char *size_str = opts->args[0];
    const char *key_path = opts->args[1];

    /* Parse size — support suffixes: K, M, G */
    uint64_t size = 0;
    char *end = NULL;
    unsigned long long raw = strtoull(size_str, &end, 10);

    if (end && *end != '\0') {
        switch (*end) {
            case 'K': case 'k': raw *= 1024ULL; break;
            case 'M': case 'm': raw *= 1024ULL * 1024ULL; break;
            case 'G': case 'g': raw *= 1024ULL * 1024ULL * 1024ULL; break;
            default:
                LOG_ERROR("Invalid size suffix '%c'. Use K, M, or G (e.g. 10M)", *end);
                return 1;
        }
    }
    size = (uint64_t)raw;

    if (size == 0) {
        LOG_ERROR("Key size must be greater than 0");
        return 1;
    }

    LOG_INFO("Mode:    GENERATE KEY");
    LOG_INFO("Size:    %llu bytes (%.2f MB)", (unsigned long long)size,
             (double)size / (1024.0 * 1024.0));
    LOG_INFO("Output:  %s", key_path);
    printf("\n");

    /* Ensure the parent directory of the key file exists */
    {
        char key_dir[MAX_PATH];
        strncpy(key_dir, key_path, sizeof(key_dir) - 1);
        key_dir[sizeof(key_dir) - 1] = '\0';
        char *last_sep = strrchr(key_dir, '\\');
        if (!last_sep) last_sep = strrchr(key_dir, '/');
        if (last_sep) {
            *last_sep = '\0';
            fio_ensure_dir(key_dir);
        }
    }

    /* Check that no key already exists at this path (prevent overwrite) */
    if (fio_path_exists(key_path)) {
        LOG_ERROR("Key file already exists: %s", key_path);
        LOG_WARN("Delete the existing key manually if you intend to replace it.");
        return 1;
    }

    OtpStatus s = otp_generate_key(key_path, size);
    if (s != OTP_OK) {
        LOG_ERROR("Key generation failed: %s", otp_status_str(s));
        return 1;
    }
    return 0;
}

/* ── Mode: Verify ────────────────────────────────────────────────────────── */
static int do_verify(const CliOptions *opts)
{
    if (opts->arg_count < 2) {
        LOG_ERROR("Verify mode requires 2 arguments: <file> <sha256_hex>");
        return 1;
    }

    const char *file_path   = opts->args[0];
    const char *expected_hex = opts->args[1];

    if (strlen(expected_hex) != SHA256_DIGEST_BYTES * 2) {
        LOG_ERROR("Expected SHA-256 hex must be exactly 64 characters");
        return 1;
    }

    LOG_INFO("Mode:    VERIFY");
    LOG_INFO("File:    %s", file_path);
    LOG_INFO("Expected:%s", expected_hex);
    printf("\n");

    unsigned char digest[SHA256_DIGEST_BYTES];
    CryptoStatus cs = crypto_sha256_file(file_path, digest);
    if (cs != CRYPTO_OK) {
        LOG_ERROR("Failed to compute SHA-256 for: %s", file_path);
        return 1;
    }

    char computed_hex[SHA256_DIGEST_BYTES * 2 + 1];
    crypto_hex_string(digest, SHA256_DIGEST_BYTES, computed_hex);

    LOG_INFO("Computed: %s", computed_hex);

    /* Case-insensitive comparison */
    char exp_lower[SHA256_DIGEST_BYTES * 2 + 1];
    for (int i = 0; i < (int)strlen(expected_hex); i++) {
        char c = expected_hex[i];
        exp_lower[i] = (c >= 'A' && c <= 'F') ? (char)(c + 32) : c;
    }
    exp_lower[SHA256_DIGEST_BYTES * 2] = '\0';

    if (strcmp(computed_hex, exp_lower) == 0) {
        LOG_SUCCESS("File integrity verified: SHA-256 matches");
        return 0;
    } else {
        LOG_ERROR("INTEGRITY FAILURE: SHA-256 does NOT match");
        return 1;
    }
}

/* ── Batch mode (encrypt all files in a directory) ───────────────────────── */
static int do_batch_encrypt(const CliOptions *opts)
{
    if (opts->arg_count < 3) {
        LOG_ERROR("Batch encrypt requires: <input_dir> <output_dir> <key_dir>");
        return 1;
    }

    const char *in_dir  = opts->args[0];
    const char *out_dir = opts->args[1];
    const char *key_dir = opts->args[2];

    LOG_INFO("Mode:     BATCH ENCRYPT");
    LOG_INFO("Input:    %s", in_dir);
    LOG_INFO("Output:   %s", out_dir);
    LOG_INFO("Keys:     %s", key_dir);
    printf("\n");

    fio_ensure_dir(out_dir);
    fio_ensure_dir(key_dir);

    /* Enumerate files in input directory */
    char search_pattern[MAX_PATH];
    snprintf(search_pattern, sizeof(search_pattern), "%s\\*", in_dir);

    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_pattern, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Cannot enumerate input directory: %s", in_dir);
        return 1;
    }

    int files_processed = 0;
    int files_failed    = 0;

    do {
        /* Skip directories and hidden files */
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)    continue;

        const char *filename = find_data.cFileName;

        /* Skip already-encrypted files */
        const char *ext = strrchr(filename, '.');
        if (ext && strcmp(ext, ".enc") == 0) {
            LOG_VERBOSE("Skipping already-encrypted file: %s", filename);
            continue;
        }

        /* Build paths */
        char in_path[MAX_PATH], out_path[MAX_PATH], key_path[MAX_PATH];
        snprintf(in_path,  sizeof(in_path),  "%s\\%s",      in_dir,  filename);
        snprintf(out_path, sizeof(out_path), "%s\\%s.enc",  out_dir, filename);
        snprintf(key_path, sizeof(key_path), "%s\\%s.key",  key_dir, filename);

        LOG_INFO("Processing: %s", filename);

        /* Determine file size for key generation */
        FILE *fp = NULL;
        FioStatus fs = fio_open_read(in_path, &fp);
        if (fs != FIO_OK) {
            LOG_ERROR("Cannot read: %s — skipping", in_path);
            files_failed++;
            continue;
        }
        uint64_t file_size = 0;
        fio_get_size(fp, &file_size);
        fclose(fp);

        /* Generate key */
        if (!fio_path_exists(key_path)) {
            OtpStatus gs = otp_generate_key(key_path, file_size);
            if (gs != OTP_OK) {
                LOG_ERROR("Key generation failed for: %s — skipping", filename);
                files_failed++;
                continue;
            }
        } else {
            LOG_VERBOSE("Using existing key: %s", key_path);
        }

        /* Encrypt */
        OtpStatus es = otp_encrypt(in_path, out_path, key_path,
                                    progress_callback, (void *)"Encrypting");
        log_progress_done();

        if (es != OTP_OK) {
            LOG_ERROR("Encryption failed for '%s': %s", filename, otp_status_str(es));
            files_failed++;
        } else {
            files_processed++;
        }

    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);

    printf("\n");
    LOG_INFO("Batch complete: %d encrypted, %d failed", files_processed, files_failed);
    return (files_failed > 0) ? 1 : 0;
}

/* ── Self-test mode ─────────────────────────────────────────────────────────── */
/*
 * Performs an internal round-trip encrypt/decrypt on a 64-byte known
 * plaintext blob using temporary files.  Verifies:
 *   1. BCryptGenRandom produces a key of correct size.
 *   2. Encryption produces a file of exactly HEADER + 64 bytes.
 *   3. Decryption recovers byte-for-byte identical plaintext.
 *   4. SHA-256 integrity check passes automatically.
 *   5. Key lock prevents re-use (tries to encrypt again, must fail).
 *
 * All temporary files are cleaned up on exit.
 * Returns 0 on full pass, 1 on first failure.
 */
static int do_selftest(void)
{
    static const unsigned char TEST_PLAINTEXT[] =
        "OTP-SELFTEST-v1.0 | ABCDEFGHIJKLMNOPQRSTUVWXYZ | 0123456789!@#$"; /* 64 bytes */
    const size_t PT_SIZE = sizeof(TEST_PLAINTEXT) - 1; /* exclude \0 */

    /* Temp file paths in the system TEMP directory */
    char tmp_pt[MAX_PATH], tmp_enc[MAX_PATH], tmp_dec[MAX_PATH], tmp_key[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_pt);
    tmp_pt[MAX_PATH - 1] = '\0';

    strncpy(tmp_enc, tmp_pt, MAX_PATH - 1); tmp_enc[MAX_PATH - 1] = '\0';
    strncpy(tmp_dec, tmp_pt, MAX_PATH - 1); tmp_dec[MAX_PATH - 1] = '\0';
    strncpy(tmp_key, tmp_pt, MAX_PATH - 1); tmp_key[MAX_PATH - 1] = '\0';

    strncat(tmp_pt,  "otp_st_plain.bin",    MAX_PATH - strlen(tmp_pt)  - 1);
    strncat(tmp_enc, "otp_st_cipher.enc",   MAX_PATH - strlen(tmp_enc) - 1);
    strncat(tmp_dec, "otp_st_recovered.bin",MAX_PATH - strlen(tmp_dec) - 1);
    strncat(tmp_key, "otp_st_key.bin",      MAX_PATH - strlen(tmp_key) - 1);

    /* Remove stale temp files from a previous failed run */
    remove(tmp_pt); remove(tmp_enc); remove(tmp_dec); remove(tmp_key);
    {
        char lock[MAX_PATH];
        if (fio_lock_path(tmp_key, lock, sizeof(lock)) == 0) remove(lock);
    }

    int failed = 0;
    int passed = 0;

    LOG_INFO("============================================================");
    LOG_INFO(" OTP Tool Self-Test  v%s", OTP_VERSION_STR);
    LOG_INFO("============================================================");

    /* ── Test 1: Write known plaintext ──────────────────────────────── */
    LOG_INFO("[1/5] Writing known plaintext (%zu bytes)...", PT_SIZE);
    {
        FILE *fp = fopen(tmp_pt, "wb");
        if (!fp) {
            LOG_ERROR("Cannot create temp plaintext: %s", tmp_pt);
            return 1;
        }
        if (fwrite(TEST_PLAINTEXT, 1, PT_SIZE, fp) != PT_SIZE) {
            fclose(fp); LOG_ERROR("Write failed"); return 1;
        }
        fclose(fp);
    }
    LOG_SUCCESS("[1/5] PASS: Plaintext written");
    passed++;

    /* ── Test 2: Generate key ────────────────────────────────────────── */
    LOG_INFO("[2/5] Generating cryptographic key (%zu bytes)...", PT_SIZE);
    {
        OtpStatus s = otp_generate_key(tmp_key, (uint64_t)PT_SIZE);
        if (s != OTP_OK) {
            LOG_ERROR("[2/5] FAIL: Key generation: %s", otp_status_str(s));
            failed++;
        } else {
            LOG_SUCCESS("[2/5] PASS: Key generated via BCryptGenRandom");
            passed++;
        }
    }
    if (failed) goto selftest_cleanup;

    /* ── Test 3: Encrypt ─────────────────────────────────────────────── */
    LOG_INFO("[3/5] Encrypting...");
    {
        OtpStatus s = otp_encrypt(tmp_pt, tmp_enc, tmp_key, NULL, NULL);
        if (s != OTP_OK) {
            LOG_ERROR("[3/5] FAIL: Encryption: %s", otp_status_str(s));
            failed++;
        } else {
            /* Verify output size = HEADER + PT_SIZE */
            FILE *fp = fopen(tmp_enc, "rb");
            uint64_t enc_size = 0;
            if (fp) { fio_get_size(fp, &enc_size); fclose(fp); }
            if (enc_size != OTP_HEADER_SIZE + PT_SIZE) {
                LOG_ERROR("[3/5] FAIL: Encrypted file size is %llu, expected %llu",
                          (unsigned long long)enc_size,
                          (unsigned long long)(OTP_HEADER_SIZE + PT_SIZE));
                failed++;
            } else {
                LOG_SUCCESS("[3/5] PASS: Encrypted (%llu bytes = header + plaintext)",
                            (unsigned long long)enc_size);
                passed++;
            }
        }
    }
    if (failed) goto selftest_cleanup;

    /* ── Test 4: Decrypt + integrity ─────────────────────────────────── */
    LOG_INFO("[4/5] Decrypting and verifying SHA-256 integrity...");
    {
        OtpStatus s = otp_decrypt(tmp_enc, tmp_key, tmp_dec, NULL, NULL);
        if (s != OTP_OK) {
            LOG_ERROR("[4/5] FAIL: Decryption / integrity: %s", otp_status_str(s));
            failed++;
        } else {
            /* Byte-compare decrypted output to original plaintext */
            FILE *fp = fopen(tmp_dec, "rb");
            int match = 0;
            if (fp) {
                unsigned char recovered[sizeof(TEST_PLAINTEXT)];
                size_t n = fread(recovered, 1, sizeof(recovered), fp);
                fclose(fp);
                match = (n == PT_SIZE &&
                         memcmp(recovered, TEST_PLAINTEXT, PT_SIZE) == 0);
            }
            if (!match) {
                LOG_ERROR("[4/5] FAIL: Decrypted data does not match original plaintext!");
                failed++;
            } else {
                LOG_SUCCESS("[4/5] PASS: Decryption correct + SHA-256 verified");
                passed++;
            }
        }
    }
    if (failed) goto selftest_cleanup;

    /* ── Test 5: Key reuse protection ────────────────────────────────── */
    LOG_INFO("[5/5] Verifying key reuse protection...");
    {
        /* Key should be locked; trying to encrypt again must fail */
        OtpStatus s = otp_encrypt(tmp_pt, tmp_enc, tmp_key, NULL, NULL);
        if (s == OTP_ERR_KEY_LOCKED) {
            LOG_SUCCESS("[5/5] PASS: Key reuse correctly rejected");
            passed++;
        } else {
            LOG_ERROR("[5/5] FAIL: Key reuse was not rejected! (got %s)",
                      otp_status_str(s));
            failed++;
        }
    }

selftest_cleanup:
    remove(tmp_pt); remove(tmp_enc); remove(tmp_dec);
    fio_secure_delete(tmp_key);
    {
        char lock[MAX_PATH];
        if (fio_lock_path(tmp_key, lock, sizeof(lock)) == 0) remove(lock);
    }

    printf("\n");
    LOG_INFO("============================================================");
    LOG_INFO(" Results: %d passed, %d failed", passed, failed);
    LOG_INFO("============================================================");

    if (failed == 0) {
        LOG_SUCCESS("ALL TESTS PASSED — OTP engine is operating correctly");
        return 0;
    } else {
        LOG_ERROR("SELF-TEST FAILED — %d test(s) did not pass", failed);
        return 1;
    }
}

/* ── main ────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    CliOptions opts = parse_args(argc, argv);

    /* Initialise logger first */
    log_init(opts.verbose ? LOG_VERBOSE : LOG_NORMAL);

    if (opts.show_help || argc < 2) {
        print_help();
        return 0;
    }

    if (opts.show_version) {
        printf("OTP Encryption Tool v%s\n", OTP_VERSION_STR);
        printf("Built: %s %s\n", __DATE__, __TIME__);
        return 0;
    }

    if (!opts.mode && !opts.selftest) {
        LOG_ERROR("No mode specified. Use -e, -d, -g, --verify, or --selftest.");
        LOG_INFO("Run 'otp.exe --help' for usage.");
        return 1;
    }

    print_banner();

    /* Handle --selftest before mode dispatch */
    if (opts.selftest) {
        return do_selftest();
    }

    if (opts.batch_mode) {
        if (strcmp(opts.mode, "-e") == 0) {
            return do_batch_encrypt(&opts);
        } else {
            LOG_ERROR("Batch mode only supports -e (encrypt). Use -d per-file.");
            return 1;
        }
    }

    if (strcmp(opts.mode, "-e") == 0) {
        return do_encrypt(&opts);
    } else if (strcmp(opts.mode, "-d") == 0) {
        return do_decrypt(&opts);
    } else if (strcmp(opts.mode, "-g") == 0) {
        return do_generate(&opts);
    } else if (strcmp(opts.mode, "--verify") == 0) {
        return do_verify(&opts);
    } else {
        LOG_ERROR("Unknown mode: %s", opts.mode);
        return 1;
    }
}
