# =============================================================================
# Makefile — OTP File Encryption Tool
#
# Targets:
#   make           — build otp.exe (default)
#   make clean     — remove build artifacts
#   make test      — run a quick encrypt/decrypt round-trip test
#   make selftest  — run the built-in cryptographic self-test
#   make release   — build with full optimisations (-O3 -march=native)
#
# Requirements:
#   MinGW-w64 gcc on PATH  (https://www.mingw-w64.org/)
#   bcrypt is a Windows system library — no extra download needed
#
# Usage:
#   mingw32-make
#   mingw32-make test
#   mingw32-make selftest
# =============================================================================

CC      := gcc
TARGET  := build\otp.exe

SRCS    := src\main.c      \
           src\otp.c       \
           src\file_io.c   \
           src\crypto_win.c \
           src\logger.c

OBJS    := $(patsubst src\%.c, build\%.o, $(SRCS))

# ── Compiler flags ────────────────────────────────────────────────────────────
CFLAGS  := -Wall -Wextra              \
            -Wformat=2                \
            -Wno-unused-parameter     \
            -std=c11                  \
            -O2                       \
            -I src

# ── Linker flags ──────────────────────────────────────────────────────────────
LDFLAGS := -lbcrypt

# ── Default target ────────────────────────────────────────────────────────────
all: dirs $(TARGET)
	@echo.
	@echo [INFO] Run: build\otp.exe --selftest
	@echo [INFO] Run: build\otp.exe --help

dirs:
	@if not exist build       mkdir build
	@if not exist input_files mkdir input_files
	@if not exist output_files mkdir output_files
	@if not exist keys        mkdir keys

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo.
	@echo [SUCCESS] Built: $(TARGET)

build\%.o: src\%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Release build ─────────────────────────────────────────────────────────────
release: CFLAGS += -O3 -DNDEBUG -march=native
release: clean all
	@echo [SUCCESS] Release build complete.

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	@if exist build\*.o   del /Q build\*.o
	@if exist build\*.exe del /Q build\*.exe
	@echo [INFO] Build directory cleaned.

# ── Built-in self-test (5 steps) ──────────────────────────────────────────────
selftest: all
	@echo.
	$(TARGET) --selftest

# ── Unit Tests ────────────────────────────────────────────────────────────────
# Builds and runs the comprehensive test suite in tests/
test: all
	$(MAKE) -C tests run

# ── Code Formatting ───────────────────────────────────────────────────────────
format:
	@echo [INFO] Running clang-format...
	clang-format -i src/*.c src/*.h tests/*.c tests/*.h
	@echo [SUCCESS] Formatting complete.

.PHONY: all clean test selftest release dirs format
