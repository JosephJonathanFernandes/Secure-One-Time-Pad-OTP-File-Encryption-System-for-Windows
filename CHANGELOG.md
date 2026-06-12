# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-12
### Added
- True One-Time Pad (XOR) streaming encryption/decryption.
- FIPS-compliant key generation via `BCryptGenRandom` (Windows CNG).
- Embedded SHA-256 integrity verification.
- `.lock` sidecar files to prevent accidental key reuse.
- `--self-destruct-key` flag for secure 3-pass file deletion.
- `--batch -e` directory encryption.
- Built-in `--selftest` 5-step validation.
- Progress bar and colored ANSI logging.
- Comprehensive zero-dependency unit test suite.
- GitHub Actions CI workflow.
