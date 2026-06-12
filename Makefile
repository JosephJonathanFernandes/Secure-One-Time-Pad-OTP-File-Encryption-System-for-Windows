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

# ── Quick round-trip test ─────────────────────────────────────────────────────
# Creates a test file, generates a key, encrypts, decrypts, compares with fc.
test: all
	@echo ============================================================
	@echo  OTP Tool Round-Trip Test
	@echo ============================================================
	@echo This is a round-trip test of the OTP encryption system. > input_files\test_input.txt
	@if exist keys\test.key        del /Q keys\test.key
	@if exist keys\test.key.lock   del /Q keys\test.key.lock
	@if exist output_files\test_output.enc     del /Q output_files\test_output.enc
	@if exist output_files\test_recovered.txt  del /Q output_files\test_recovered.txt
	@echo [1/3] Generating key...
	$(TARGET) -g 4096 keys\test.key
	@echo [2/3] Encrypting...
	$(TARGET) -e input_files\test_input.txt output_files\test_output.enc keys\test.key
	@echo [3/3] Decrypting...
	$(TARGET) -d output_files\test_output.enc keys\test.key output_files\test_recovered.txt
	@echo Comparing...
	@fc /b input_files\test_input.txt output_files\test_recovered.txt > nul && \
	    (echo [SUCCESS] Round-trip test PASSED!) || \
	    (echo [ERROR] Round-trip test FAILED - files differ! & exit 1)

.PHONY: all clean test selftest release dirs
