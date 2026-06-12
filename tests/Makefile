# =============================================================================
# Makefile — OTP Tests
#
# Builds the test executables and runs them.
# =============================================================================

SHELL   := cmd.exe
CC      := gcc
CFLAGS  := -Wall -Wextra -Wformat=2 -Wno-unused-parameter -std=c11 -O0 -g -I ../src
LDFLAGS := -lbcrypt

# Core source files (excluding main.c)
CORE_SRCS := ../src/otp.c ../src/crypto_win.c ../src/file_io.c ../src/logger.c

# Test binaries
TEST_BINS := test_otp.exe test_crypto.exe test_file_io.exe

all: $(TEST_BINS) run

%.exe: %.c $(CORE_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

run: $(TEST_BINS)
	@echo.
	@echo Running tests...
	@.\test_crypto.exe
	@.\test_file_io.exe
	@.\test_otp.exe
	@echo All test suites completed.

clean:
	@if exist *.exe del /Q *.exe
	@if exist tmp_*.* del /Q tmp_*.*
	@if exist fio_*.* del /Q fio_*.*
	@if exist otp_st_*.* del /Q otp_st_*.*

.PHONY: all run clean
