@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo  OTP Tool - Git Push to GitHub
echo ============================================================
echo.

REM ── Sanity checks ────────────────────────────────────────────────────────────
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] git not found in PATH.
    echo Install Git for Windows: https://git-scm.com/download/win
    exit /b 1
)

echo [INFO] Git version:
git --version
echo.

REM ── Show current status ───────────────────────────────────────────────────────
echo [INFO] Current git status:
git status --short
echo.

REM ── Stage all project files ───────────────────────────────────────────────────
echo [INFO] Staging all files...
git add src\main.c
git add src\otp.c
git add src\otp.h
git add src\file_io.c
git add src\file_io.h
git add src\crypto_win.c
git add src\crypto_win.h
git add src\logger.c
git add src\logger.h
git add Makefile
git add build.bat
git add README.md
git add .gitignore

echo.
echo [INFO] Files staged:
git status --short
echo.

REM ── Commit ───────────────────────────────────────────────────────────────────
echo [INFO] Committing...
git commit -m "feat: production-grade OTP file encryption system v1.0.0

- True One-Time Pad (XOR) encryption/decryption
- BCryptGenRandom (Windows CNG / FIPS 140-2) for key generation
- SHA-256 integrity verification on every decryption
- Streaming 8 KB chunked I/O - safe for GB-scale files
- Key reuse prevention via .lock sidecar files
- Secure 3-pass key deletion (--self-destruct-key)
- Batch directory encryption (--batch -e)
- SHA-256 file verification (--verify)
- Built-in 5-step cryptographic self-test (--selftest)
- Progress bar with MB display
- ANSI coloured output (Windows VT processing)
- No external dependencies - pure Windows CNG"

if %errorlevel% neq 0 (
    echo.
    echo [WARN] Commit failed - may already be committed or nothing to commit.
)

echo.

REM ── Check remote ─────────────────────────────────────────────────────────────
echo [INFO] Configured remotes:
git remote -v
echo.

REM ── Push ─────────────────────────────────────────────────────────────────────
echo [INFO] Pushing to origin...
git push -u origin main 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [INFO] Trying 'master' branch instead of 'main'...
    git push -u origin master 2>&1
    if %errorlevel% neq 0 (
        echo.
        echo [ERROR] Push failed. See errors above.
        echo.
        echo Common fixes:
        echo   1. No remote configured yet:
        echo      git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
        echo      git push -u origin main
        echo.
        echo   2. Auth issue:
        echo      git config --global credential.helper manager
        echo      (then try push again - browser login will open)
        echo.
        echo   3. Wrong branch name - check with:
        echo      git branch
        exit /b 1
    )
)

echo.
echo [SUCCESS] Pushed to GitHub!
echo.
echo ── Next Steps ───────────────────────────────────────────────────────────────
echo   - Add repository description on GitHub
echo   - Add topics: c, encryption, one-time-pad, cryptography, windows
echo   - Add a GitHub Actions CI workflow (optional)
echo.
