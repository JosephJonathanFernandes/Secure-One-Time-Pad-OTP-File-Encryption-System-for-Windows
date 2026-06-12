@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo  OTP Tool - Git Push to GitHub
echo ============================================================
echo.

REM ── Sanity checks ────────────────────────────────────────────────────────────
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] git not found in PATH or failed to execute.
    echo Install Git for Windows: https://git-scm.com/download/win
    exit /b 1
)

echo [INFO] Git version:
git --version
echo.

REM ── Go to project root (since script is in scripts/) ──────────────────────────
cd /d "%~dp0.."

REM ── Show current status ───────────────────────────────────────────────────────
echo [INFO] Current git status:
git status --short
echo.

REM ── Stage all project files ───────────────────────────────────────────────────
echo [INFO] Staging all files...
git add src/
git add tests/
git add docs/
git add scripts/
git add config/
git add .github/
git add Makefile
git add README.md
git add CONTRIBUTING.md
git add CHANGELOG.md
git add .gitignore
git add .clang-format

echo.
echo [INFO] Files staged:
git status --short
echo.

REM ── Commit ───────────────────────────────────────────────────────────────────
echo [INFO] Committing...
git commit -m "refactor: enterprise-grade restructuring and QA

- Reorganized project into /src, /tests, /docs, /scripts, /config, /.github
- Added zero-dependency single-header test framework (test_runner.h)
- Implemented comprehensive unit tests for core, crypto, and I/O logic
- Configured GitHub Actions CI pipeline for Windows MinGW build/test
- Added architecture and security model documentation
- Added CONTRIBUTING.md, CHANGELOG.md, and .clang-format (Google style)
- Rewrote README to recruiter/enterprise standards
- Core cryptography implementation remains unmodified"

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
echo   - Check the Actions tab on GitHub to see the CI pipeline run
echo.
