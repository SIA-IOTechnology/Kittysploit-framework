@echo off
setlocal enabledelayedexpansion
REM KittySploit Framework Windows Installer
REM ========================================

echo.
echo  KittySploit Framework
echo  Windows Installer
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: Python is not installed or not in PATH
    echo [!] Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo [*] Python found, checking version...
python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>nul
if %errorlevel% neq 0 (
    echo [!] Error: Python 3.8 or higher is required
    echo [!] Please upgrade Python from https://python.org
    pause
    exit /b 1
)

echo [+] Python version check passed
echo.

REM Get the project root directory
pushd "%~dp0.."
set "PROJECT_ROOT=!CD!"
popd
cd /d "!PROJECT_ROOT!"

REM Check if we're in a virtual environment
set "HAS_VENV=0"
if "!VIRTUAL_ENV!"=="" (
    echo [*] Not in a virtual environment, creating one...
    python -m venv venv
    if !errorlevel! equ 0 (
        if exist "venv\Scripts\activate.bat" (
            echo [+] Virtual environment created: venv\
            call "venv\Scripts\activate.bat"
            echo [+] Virtual environment activated
            set "HAS_VENV=1"
        )
    )
    if !HAS_VENV!==0 (
        echo [!] Warning: Failed to create virtual environment
        echo [!] Continuing without venv (packages will be installed globally)...
    )
) else (
    echo [+] Already in a virtual environment: !VIRTUAL_ENV!
)

REM Install requirements
echo [*] Installing Python requirements...
if !HAS_VENV!==1 (
    "venv\Scripts\pip.exe" install --upgrade pip
    if !errorlevel! neq 0 (
        echo [!] Error: Failed to upgrade pip
        pause
        exit /b 1
    )
    "venv\Scripts\pip.exe" install -r install/requirements.txt
    if !errorlevel! neq 0 (
        echo [!] Error: Failed to install requirements
