@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo  OTP File Encryption Tool - Build Script
echo ============================================================
echo.

REM ── Check for gcc ────────────────────────────────────────────────────────────
where gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] gcc not found in PATH.
    echo.
    echo Please install MinGW-w64 and add its bin directory to PATH.
    echo Download: https://www.mingw-w64.org/
    echo.
    echo After installation, add to PATH:
    echo   C:\mingw64\bin  (or wherever you installed it)
    exit /b 1
)

echo [INFO] Compiler:
gcc --version | head -1 2>nul || gcc --version
echo.

REM ── Go to project root (since script is in scripts/) ──────────────────────────
cd /d "%~dp0.."

REM ── Create directories ────────────────────────────────────────────────────────
if not exist build        mkdir build
if not exist input_files  mkdir input_files
if not exist output_files mkdir output_files
if not exist keys         mkdir keys

echo [INFO] Compiling all modules...
echo.

gcc ^
    -Wall -Wextra ^
    -Wformat=2 ^
    -Wno-unused-parameter ^
    -std=c11 ^
    -O2 ^
    -I src ^
    src\main.c ^
    src\otp.c ^
    src\file_io.c ^
    src\crypto_win.c ^
    src\logger.c ^
    -o build\otp.exe ^
    -lbcrypt ^
    2>&1

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build FAILED. See error messages above.
    exit /b 1
)

echo.
echo [SUCCESS] Build complete: build\otp.exe
echo.
echo ── Version ──────────────────────────────────────────────────
build\otp.exe --version
echo.
echo ── Running Self-Test ────────────────────────────────────────
build\otp.exe --selftest
echo.
echo ── Quick Start ──────────────────────────────────────────────
echo   build\otp.exe --help
echo   build\otp.exe -g 1024 keys\mykey.key
echo   build\otp.exe -e myfile.txt myfile.enc keys\mykey.key
echo   build\otp.exe -d myfile.enc keys\mykey.key myfile_dec.txt
echo.
