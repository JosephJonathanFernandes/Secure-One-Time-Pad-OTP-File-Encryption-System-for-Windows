# System Architecture

This document describes the high-level architecture and data flows of the OTP File Encryption System.

## Module Map

The project enforces strict separation of concerns to maintain a highly testable and secure core.

```text
                  ┌───────────────────────────────┐
                  │ main.c (CLI, Argument Parser) │
                  └──────┬─────────────────┬──────┘
                         │                 │
           ┌─────────────▼────┐    ┌───────▼───────────┐
           │     logger.c     │    │       otp.c       │
           │  (Progress, Log) │    │  (Core XOR Engine)│
           └──────────────────┘    └───────┬─────┬─────┘
                                           │     │
                 ┌─────────────────────────▼─┐ ┌─▼────────────────────────┐
                 │         file_io.c         │ │       crypto_win.c       │
                 │ (I/O, Key Lock Lifecycle) │ │ (CSPRNG, SHA-256, Zero)  │
                 └───────────────────────────┘ └──────────────────────────┘
```

### Module Responsibilities

| Module | Responsibility |
|---|---|
| `main.c` | CLI flags parsing, argument validation, dispatching actions, batch mode orchestration. |
| `otp.c` | Core business logic: Encrypt, Decrypt, Key generation orchestration, custom binary header reading and writing. |
| `crypto_win.c` | Cryptographic primitives using Windows CNG (`BCryptGenRandom`, `BCryptCreateHash`, `SecureZeroMemory`). This isolates all Windows-specific crypto calls. |
| `file_io.c` | Abstractions for `FILE*` operations. It handles robust large file sizes, directory creation, and the crucial `.lock` file sidecar lifecycle for keys. |
| `logger.c` | Formatted output to `stdout`/`stderr` with severity tags, timestamps, and progress bars. |

---

## Data Flow: Encryption

1. **CLI Validation**: `main.c` validates input, output, and key paths.
2. **Key Validation**: `otp.c` asks `file_io.c` to check key size and lock status.
3. **Locking**: `file_io.c` acquires a lock (`.lock` file) on the key.
4. **Header Construction**: `otp.c` uses `crypto_win.c` to hash the plaintext (`SHA-256`).
5. **Streaming**: `otp.c` reads plaintext and key in `8 KB` chunks, applies the XOR, and writes to ciphertext.
6. **Zeroization**: `crypto_win.c` `SecureZeroMemory` zeroes out local stack buffers in `otp.c` before returning.

## Data Flow: Decryption

1. **Header Validation**: `otp.c` reads the first 52 bytes, validating magic bytes (`OTP\x01`) and extracting plaintext size and expected SHA-256 hash.
2. **Key Validation**: Checks key size against extracted plaintext size.
3. **Streaming**: Reads ciphertext and key in chunks, applies XOR, and writes plaintext.
4. **Integrity Check**: Re-hashes the decrypted output and compares it to the expected hash in the header. If it mismatches, it returns `OTP_ERR_HASH_MISMATCH` and issues a `[WARNING]`.

---

## Encrypted File Format Spec (`.enc`)

Every encrypted file begins with a custom 52-byte binary header.

| Offset | Size (Bytes) | Field Name | Description |
|---|---|---|---|
| `0` | `4` | Magic Bytes | `"OTP\x01"` - Identifies the file type and version. |
| `4` | `8` | Plaintext Size | `uint64_t` (Little-Endian) - Original size in bytes. |
| `12` | `32` | SHA-256 Digest | Raw 32-byte digest of the unencrypted plaintext. |
| `44` | `8` | Reserved | Currently zero-padded `0x00`. For future expansion. |
| `52` | `N` | Ciphertext | The XOR-encrypted payload where `N` is Plaintext Size. |

**Total File Size** = `52 + Plaintext Size`.
