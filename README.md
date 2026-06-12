# OTP File Encryption Tool

> **Production-grade One-Time Pad file encryption for Windows.**
> Built in C11, powered by Windows CNG (`BCryptGenRandom` + `BCrypt SHA-256`).

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Security Model](#security-model)
4. [Building](#building)
5. [Usage](#usage)
6. [File Format](#file-format)
7. [OTP Limitations](#otp-limitations)
8. [Self-Test](#self-test)

---

## Features

| Feature | Detail |
|---|---|
| **True OTP encryption** | XOR with cryptographically random key, never reused |
| **CSPRNG** | `BCryptGenRandom` (FIPS 140-2 system RNG) |
| **Large file support** | Streaming 8 KB chunks — never loads whole file into RAM |
| **SHA-256 integrity** | Embedded in ciphertext header; verified on every decrypt |
| **Key reuse prevention** | `.lock` sidecar file; engine refuses to use a locked key |
| **Secure key deletion** | 3-pass overwrite (0x00 / 0xFF / 0x00) then `remove()` |
| **Progress bar** | Live MB/s progress on encrypt/decrypt |
| **Batch encryption** | Encrypt all files in a directory in one command |
| **Self-test mode** | Built-in 5-step round-trip proof of correctness |
| **Coloured output** | ANSI colours via `ENABLE_VIRTUAL_TERMINAL_PROCESSING` |

---

## Architecture

```
OTP File Encryption Tool
├── src/
│   ├── main.c          CLI entry point, argument parser, mode dispatcher
│   ├── otp.c / otp.h   Core XOR engine, header read/write, key generation
│   ├── crypto_win.c    BCryptGenRandom, SHA-256 (file & buffer), SecureZeroMemory
│   ├── crypto_win.h
│   ├── file_io.c       Safe open/read/write, file-size query, key lock lifecycle
│   ├── file_io.h
│   ├── logger.c        Tagged, coloured, timestamped log output + progress bar
│   └── logger.h
├── build/              Compiled output (otp.exe)
├── input_files/        Sample plaintext files (not tracked by git)
├── output_files/       Encrypted and decrypted outputs (not tracked by git)
├── keys/               Key files (NEVER commit these to version control)
├── Makefile            MinGW-w64 build (mingw32-make)
├── build.bat           Alternative cmd.exe build script
└── README.md
```

### Module responsibilities

| Module | Responsibility |
|---|---|
| `main.c` | Parses CLI args, calls mode handlers, owns the progress callback |
| `otp.c` | `otp_encrypt`, `otp_decrypt`, `otp_generate_key`, header I/O |
| `crypto_win.c` | All Windows CNG calls; zero platform-specific code leaks out |
| `file_io.c` | All `FILE*` operations; key lock `.lock` sidecar files |
| `logger.c` | All `printf`/`fprintf` calls go through this layer |

---

## Security Model

### What OTP guarantees

A One-Time Pad is **information-theoretically secure** when used correctly:

* An adversary who intercepts the ciphertext learns **zero bits** of the plaintext,
  even with unlimited compute — because every plaintext is equally likely under a
  random key.

### What this implementation ensures

1. **Cryptographically random keys** — `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`
   uses the Windows CSPRNG (Fortuna-based, FIPS 140-2 certified when in FIPS mode).

2. **Key size = plaintext size** — The tool validates this before any operation.

3. **One key, one use** — A `.lock` sidecar is created atomically before the first
   byte is written. Even a crash mid-encryption leaves the key permanently locked.

4. **Integrity checking** — SHA-256 of the plaintext is stored in the `.enc` header.
   After decryption, the digest is recomputed and compared byte-for-byte.

5. **Memory hygiene** — All key/plaintext/ciphertext stack buffers are wiped with
   `SecureZeroMemory` after use. This prevents compiler optimisation from eliding
   the zeroing.

6. **No weak randomness** — `rand()`, `srand()`, `time()` seeds are never used for
   key material.

### What this implementation does NOT guarantee

* **Forward secrecy** — The key file on disk is the single point of failure.
  Protect it with filesystem ACLs, hardware security modules, or encrypted storage.
* **Side-channel resistance** — The XOR loop is not timing-hardened.
* **Deniability** — The `.enc` file header contains a magic number `OTP\x01` which
  identifies it as OTP-encrypted.
* **SSD secure erasure** — `fio_secure_delete` overwrites file contents, but SSDs
  may retain data in wear-levelling blocks. For high-assurance environments, use
  full-disk encryption.

---

## Building

### Requirements

* Windows 10 or 11 (64-bit)
* [MinGW-w64](https://www.mingw-w64.org/) with `gcc` and `mingw32-make` on `PATH`
  — or — Visual Studio (MSVC) with Developer Command Prompt

### MinGW-w64 (recommended)

```bat
:: Quick build (cmd.exe)
build.bat

:: Or via Makefile
mingw32-make

:: Release build (full optimisations)
mingw32-make release

:: Run self-test to verify the build
build\otp.exe --selftest
```

### MSVC (Visual Studio Developer Prompt)

```bat
cl.exe /W4 /std:c11 /O2 /I src ^
  src\main.c src\otp.c src\file_io.c src\crypto_win.c src\logger.c ^
  /Fe:build\otp.exe ^
  /link bcrypt.lib
```

### GCC flags explained

| Flag | Purpose |
|---|---|
| `-std=c11` | C11 standard |
| `-Wall -Wextra -Wpedantic` | Maximum warnings |
| `-Wformat=2` | Strict format-string checking |
| `-O2` | Standard optimisations |
| `-lbcrypt` | Link Windows CNG library |

---

## Usage

### Generate a key

```bat
otp.exe -g <size_bytes> <key.bin>

:: Examples:
otp.exe -g 4096 keys\small.key
otp.exe -g 10M  keys\ten_mb.key
otp.exe -g 1G   keys\one_gb.key
```

Size suffixes: `K` (kilobytes), `M` (megabytes), `G` (gigabytes).

### Encrypt a file

```bat
otp.exe -e <input> <output.enc> <key.bin>

:: Example:
otp.exe -e input_files\secret.txt output_files\secret.enc keys\secret.key
```

The key file will be **locked** after this operation. Do not reuse it.

### Decrypt a file

```bat
otp.exe -d <input.enc> <key.bin> <output>

:: Example:
otp.exe -d output_files\secret.enc keys\secret.key output_files\recovered.txt

:: Securely delete key after decryption:
otp.exe -d secret.enc secret.key out.txt --self-destruct-key
```

### Verify a file's SHA-256 hash

```bat
otp.exe --verify <file> <sha256_hex>

:: Example:
otp.exe --verify output_files\secret.enc a3f1c2...
```

### Batch encrypt a directory

```bat
otp.exe --batch -e <input_dir> <output_dir> <key_dir>

:: Example:
otp.exe --batch -e input_files output_files keys
```

Each file in `input_dir` gets its own key in `key_dir`.

### Optional flags

| Flag | Effect |
|---|---|
| `-v` / `--verbose` | Enable debug timestamps and extra diagnostics |
| `--self-destruct-key` | 3-pass wipe + delete key on successful decrypt |
| `--version` | Print version string |
| `-h` / `--help` | Print help |
| `--selftest` | Run internal 5-step round-trip test |

---

## File Format

Encrypted files use a 52-byte binary header followed by raw ciphertext:

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────
0       4     Magic: "OTP\x01" (identifies OTP files)
4       8     Plaintext size (uint64, little-endian)
12      32    SHA-256 of original plaintext
44      8     Reserved (zeroed, for future use)
52      N     Ciphertext (N = plaintext_size bytes)
──────  ────  ─────────────────────────────────────────
Total: 52 + N bytes
```

The key file is a raw binary file containing exactly N bytes of random data.

---

## OTP Limitations

One-Time Pad is information-theoretically perfect, but operationally demanding:

| Limitation | Impact |
|---|---|
| **Key = file size** | A 1 GB file requires a 1 GB key |
| **Key distribution** | Communicating the key securely is as hard as communicating the message |
| **No key reuse** | Each encryption needs a fresh key |
| **No authentication** | OTP alone provides confidentiality only; this tool adds SHA-256 integrity |
| **Key management** | Lost key = irrecoverable ciphertext |

For most real-world use cases, **AES-256-GCM** is preferable to OTP because it has
manageable key sizes and built-in authentication. OTP is ideal for:

* Demonstrating information-theoretic security in academic settings
* Pre-shared key scenarios where key distribution is feasible (e.g., air-gapped systems)
* Portfolio projects demonstrating cryptographic understanding

---

## Self-Test

Run the built-in cryptographic self-test:

```bat
build\otp.exe --selftest
```

The test performs 5 checks:

| Step | What is verified |
|---|---|
| 1 | Known 64-byte plaintext is written to a temp file |
| 2 | `BCryptGenRandom` generates a key of the correct size |
| 3 | Encryption produces header + ciphertext of the right length |
| 4 | Decryption recovers byte-identical plaintext + SHA-256 matches |
| 5 | Attempting to reuse the key is rejected (`OTP_ERR_KEY_LOCKED`) |

Expected output: `ALL TESTS PASSED — OTP engine is operating correctly`

All temp files are cleaned up automatically.

---

## Example Round-Trip

```bat
:: 1. Create test directories
mkdir input_files output_files keys

:: 2. Create a sample file
echo This is my secret message > input_files\message.txt

:: 3. Generate key (auto-sizes to file)
otp.exe -g 1024 keys\message.key

:: 4. Encrypt
otp.exe -e input_files\message.txt output_files\message.enc keys\message.key

:: 5. Decrypt
otp.exe -d output_files\message.enc keys\message.key output_files\message_dec.txt

:: 6. Compare
fc input_files\message.txt output_files\message_dec.txt
```

---

*Built with Windows CNG — no external crypto libraries required.*
