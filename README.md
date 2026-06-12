# OTP File Encryption System

[![CI](https://github.com/JosephJonathanFernandes/Secure-One-Time-Pad-OTP-File-Encryption-System-for-Windows/actions/workflows/ci.yml/badge.svg)](https://github.com/JosephJonathanFernandes/Secure-One-Time-Pad-OTP-File-Encryption-System-for-Windows/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language: C11](https://img.shields.io/badge/Language-C11-00599C.svg)](https://en.cppreference.com/w/c/11)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6.svg)](https://microsoft.com)

> **A production-grade, cryptographically strict One-Time Pad (OTP) file encryption system built in pure C11 for Windows.**

## 🎯 The Problem & Purpose

The One-Time Pad is the only encryption algorithm mathematically proven to be **Information-Theoretically Secure (Perfect Secrecy)**. No amount of computational power—including future quantum computers—can break it, provided the key is truly random, never reused, and kept secret.

However, OTP is notoriously difficult to implement correctly in software due to key-reuse vulnerabilities, weak random number generators, and memory leaks.

This project exists to demonstrate **secure systems programming in C** by addressing these challenges head-on. It bridges the gap between theoretical cryptography and real-world software engineering by implementing an OTP system that is actually safe to run on multi-gigabyte files.

## 🏗️ Architecture

The system is designed with strict separation of concerns, ensuring the cryptographic core is isolated from the CLI and file I/O operations.

```text
/src
 ├── main.c           # CLI parsing, validation, batch orchestration
 ├── otp.c            # Core XOR engine and header construction
 ├── crypto_win.c     # Cryptography (BCryptGenRandom, SHA-256)
 ├── file_io.c        # File handles, locking mechanisms, large file support
 └── logger.c         # Formatted output and progress tracking
```
*For detailed diagrams and the binary file format, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).*

## 🔒 Security Model & Features

This system adheres to GitGuardian security best practices and strict C programming standards.

### Core Cryptography
*   **True Randomness**: Uses `BCryptGenRandom` (Windows CNG), the FIPS 140-2 certified system CSPRNG. No `rand()` or `time()` seeds are used.
*   **Zero-Knowledge Ciphertext**: The payload leaks exactly zero bits of information about the plaintext.
*   **Integrity Verification**: Plaintext is hashed via SHA-256. The digest is embedded in the ciphertext header and verified byte-for-byte upon decryption.

### System & Memory Safety
*   **Zero-Allocation Data Path**: Processes files in streaming `8 KB` chunks. It can encrypt a 100 GB file using only a few kilobytes of RAM.
*   **Secure Zeroization**: Sensitive stack buffers are wiped using `SecureZeroMemory` before functions return, preventing compiler optimizations from eliding the cleanup.
*   **Key Reuse Prevention**: Atomic `.lock` sidecar files are generated before the first byte is encrypted. The engine refuses to operate if a key is locked.
*   **Secure Deletion**: The `--self-destruct-key` flag performs a DoD-style 3-pass overwrite (`0x00`, `0xFF`, `0x00`) before file unlinking. *(See [SECURITY.md](docs/SECURITY.md) for SSD caveats).*

## 🚀 Building & Running

### Prerequisites
*   Windows 10/11 (64-bit)
*   [MinGW-w64](https://www.mingw-w64.org/) (`gcc` and `mingw32-make` on PATH)

### Build
```cmd
:: Clone the repository
git clone https://github.com/JosephJonathanFernandes/Secure-One-Time-Pad-OTP-File-Encryption-System-for-Windows.git
cd Secure-One-Time-Pad-OTP-File-Encryption-System-for-Windows

:: Build using the provided script
scripts\build.bat

:: OR build via Makefile
mingw32-make
```

### Self-Test
The application contains a built-in cryptographic validation suite.
```cmd
build\otp.exe --selftest
```
This performs a 5-step round-trip encrypt/decrypt in memory, verifying the CSPRNG, XOR engine, SHA-256 integrity, and key locking mechanics before touching your files.

## 💻 Usage

Generate a cryptographically secure key matching your file size:
```cmd
build\otp.exe -g 1024 keys\secret.key
```

Encrypt a file:
```cmd
build\otp.exe -e input.txt output.enc keys\secret.key
```

Decrypt and securely destroy the key afterward:
```cmd
build\otp.exe -d output.enc keys\secret.key decrypted.txt --self-destruct-key
```

Batch encrypt an entire directory (1 key generated per file):
```cmd
build\otp.exe --batch -e .\documents .\encrypted_docs .\keys
```

## 🧪 Testing

This project includes a bespoke, zero-dependency unit testing framework.
```cmd
:: Run the full test suite
mingw32-make test
```
The suite covers:
*   NIST Known Answer Tests (KAT) for SHA-256
*   Encrypt/Decrypt byte-for-byte correctness
*   File lock lifecycle
*   Invalid/Corrupt header detection

## ⚠️ OTP Limitations (The Honest Truth)

While OTP provides mathematically perfect secrecy, it is rarely the right tool for production applications.
*   **Key Distribution**: You must transmit a key equal in size to your data over an already secure channel.
*   **Storage Overhead**: Encrypting a 1 TB drive requires a 1 TB key.

**For 99.9% of software engineering tasks, you should use AES-256-GCM.** This project exists as a portfolio piece to demonstrate competence in systems programming, memory safety, and applied cryptography.

## 🤝 Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for style guides, tooling, and PR processes.

## 📝 License
This project is licensed under the MIT License.
