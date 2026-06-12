# Contributing to OTP File Encryption

Thank you for your interest in contributing to this project!

## Code of Conduct
Please be respectful, professional, and collaborative in all interactions.

## Development Environment
1. Clone the repository.
2. Ensure MinGW-w64 (`gcc` and `mingw32-make`) is installed and on your `PATH`.
3. Build the project: `mingw32-make`
4. Run tests: `mingw32-make test`

## Architecture & Code Rules
* Read `docs/ARCHITECTURE.md` before making changes.
* **No external dependencies**: The core must remain pure C11 and link only against `bcrypt.lib`.
* **Zero allocations**: Prefer bounded stack buffers for small data. For large files, stream in `8 KB` chunks. Do not `malloc()` entire file payloads.
* **Security first**: Any buffers containing plaintext or key material must be cleared using `crypto_secure_zero()` before going out of scope.

## Style Guide
This project uses the Google C++ Style Guide format for C.
Before submitting a PR, format your code using `clang-format`:

```bash
clang-format -i src/*.c src/*.h
```

A `.clang-format` file is included in the repository root.

## Pull Request Process
1. Fork the repo and create your branch from `main`.
2. Write unit tests for your changes in `tests/`.
3. Ensure the GitHub Actions CI pipeline passes.
4. Provide a clear, descriptive PR message explaining *why* the change is necessary.
