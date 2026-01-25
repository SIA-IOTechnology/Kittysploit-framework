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
        echo [!] Continuing without venv ^(packages will be installed globally^)...
    )
) else (
    echo [+] Already in a virtual environment: !VIRTUAL_ENV!
)

REM Install requirements
echo [*] Installing Python requirements...
if !HAS_VENV!==1 (
    "venv\Scripts\python.exe" -m pip install --upgrade pip
    if !errorlevel! neq 0 (
        echo [!] Warning: Failed to upgrade pip, attempting to continue...
    )
    "venv\Scripts\python.exe" -m pip install -r install/requirements.txt
    if !errorlevel! neq 0 (
        echo [!] Error: Failed to install requirements
        pause
        exit /b 1
    )
) else (
    python -m pip install --upgrade pip
    if !errorlevel! neq 0 (
        echo [!] Error: Failed to upgrade pip
        pause
        exit /b 1
    )
    python -m pip install -r install/requirements.txt
    if !errorlevel! neq 0 (
        echo [!] Error: Failed to install requirements
        pause
        exit /b 1
    )
)

echo [+] Requirements installed successfully
echo.

REM Install Zig compiler
echo [*] Installing Zig compiler...
if !HAS_VENV!==1 (
    "venv\Scripts\python.exe" -c "import sys; from pathlib import Path; sys.path.insert(0, r'!PROJECT_ROOT!'); from core.lib.compiler.zig_installer import install_zig_if_needed; install_zig_if_needed(ask_confirmation=False)"
) else (
    python -c "import sys; from pathlib import Path; sys.path.insert(0, r'!PROJECT_ROOT!'); from core.lib.compiler.zig_installer import install_zig_if_needed; install_zig_if_needed(ask_confirmation=False)"
)
if !errorlevel! neq 0 (
    echo [!] Warning: Zig compiler installation failed, but continuing...
    echo [!] You can install Zig manually later or it will be installed automatically when needed
) else (
    echo [+] Zig compiler installed successfully
)
echo.

REM Create start script
echo [*] Creating start script...
if !HAS_VENV!==1 (
    (
    echo @echo off
    echo cd /d "%%~dp0"
    echo if exist "venv\Scripts\activate.bat" (
    echo     call venv\Scripts\activate.bat
    echo ^)
    echo python kittyconsole.py
    echo pause
    ) > "!PROJECT_ROOT!\start_kittysploit.bat"
) else (
    (
    echo @echo off
    echo cd /d "%%~dp0"
    echo python kittyconsole.py
    echo pause
    ) > "!PROJECT_ROOT!\start_kittysploit.bat"
)

echo [+] Start script created: start_kittysploit.bat
echo.

REM Create shortcut for start_kittysploit.bat with icon (in project root)
echo [*] Creating shortcut for start script...
(
echo import os, sys
echo try:
echo     from win32com.client import Dispatch
echo     project_root = r'!PROJECT_ROOT!'
echo     shortcut_path = os.path.join(project_root, 'KittySploit.lnk'^)
echo     target = os.path.join(project_root, 'start_kittysploit.bat'^)
echo     wDir = project_root
echo     icon_paths = [os.path.join(project_root, 'install', 'kittysploit.ico'^), os.path.join(project_root, 'kittysploit.ico'^), os.path.join(project_root, 'icon.ico'^)]
echo     icon = None
echo     for icon_path in icon_paths:
echo         if os.path.exists(icon_path^):
echo             icon = icon_path
echo             break
echo     if not icon:
echo         if os.path.exists(sys.executable^):
echo             icon = sys.executable + ',0'
echo         else:
echo             icon = 'shell32.dll,3'
echo     shell = Dispatch('WScript.Shell'^)
echo     shortcut = shell.CreateShortCut(shortcut_path^)
echo     shortcut.Targetpath = target
echo     shortcut.WorkingDirectory = wDir
echo     shortcut.IconLocation = icon
echo     shortcut.Description = 'KittySploit Framework'
echo     shortcut.save(^)
echo     print('[+] Shortcut created: KittySploit.lnk'^)
echo     if icon and not icon.startswith('shell32.dll'^):
echo         print(f'[+] Using icon: {icon}'^)
echo except ImportError:
echo     print('[!] Warning: pywin32 not installed, skipping shortcut creation'^)
echo except Exception as e:
echo     print(f'[!] Warning: Could not create shortcut: {e}'^)
) > "%TEMP%\create_shortcut.py"
if !HAS_VENV!==1 (
    "venv\Scripts\python.exe" "%TEMP%\create_shortcut.py"
) else (
    python "%TEMP%\create_shortcut.py"
)
del "%TEMP%\create_shortcut.py" 2>nul
echo.

REM Create desktop shortcut with custom icon
echo [*] Creating desktop shortcut...
(
echo import os, sys
echo try:
echo     import winshell
echo     from win32com.client import Dispatch
echo     project_root = r'!PROJECT_ROOT!'
echo     desktop = winshell.desktop(^)
echo     shortcut_path = os.path.join(desktop, 'KittySploit.lnk'^)
echo     target = os.path.join(project_root, 'start_kittysploit.bat'^)
echo     wDir = project_root
echo     icon_paths = [os.path.join(project_root, 'install', 'kittysploit.ico'^), os.path.join(project_root, 'kittysploit.ico'^), os.path.join(project_root, 'icon.ico'^)]
echo     icon = None
echo     for icon_path in icon_paths:
echo         if os.path.exists(icon_path^):
echo             icon = icon_path
echo             break
echo     if not icon:
echo         if os.path.exists(sys.executable^):
echo             icon = sys.executable + ',0'
echo         else:
echo             icon = 'shell32.dll,3'
echo     shell = Dispatch('WScript.Shell'^)
echo     shortcut = shell.CreateShortCut(shortcut_path^)
echo     shortcut.Targetpath = target
echo     shortcut.WorkingDirectory = wDir
echo     shortcut.IconLocation = icon
echo     shortcut.Description = 'KittySploit Framework'
echo     shortcut.save(^)
echo     print('[+] Desktop shortcut created successfully'^)
echo     if icon and not icon.startswith('shell32.dll'^):
echo         print(f'[+] Using icon: {icon}'^)
echo except ImportError:
echo     print('[!] Warning: winshell/pywin32 not installed, skipping desktop shortcut'^)
echo except Exception as e:
echo     print(f'[!] Warning: Could not create desktop shortcut: {e}'^)
) > "%TEMP%\create_desktop_shortcut.py"
if !HAS_VENV!==1 (
    "venv\Scripts\python.exe" "%TEMP%\create_desktop_shortcut.py"
) else (
    python "%TEMP%\create_desktop_shortcut.py"
)
del "%TEMP%\create_desktop_shortcut.py" 2>nul
echo.

REM Create uninstall script
echo [*] Creating uninstall script...
(
echo @echo off
echo echo Uninstalling KittySploit Framework...
echo echo.
echo echo This will remove:
echo if exist "venv" (
echo     echo - Virtual environment (venv\^)
echo ^)
echo echo - Python packages installed for KittySploit
echo echo - Desktop shortcut
echo echo - Start scripts
echo echo.
echo set /p confirm="Are you sure? (y/N): "
echo if /i "%%confirm%%"=="y" (
echo     echo.
echo     if exist "venv" (
echo         echo Removing virtual environment...
echo         rmdir /s /q venv
echo     ^)
echo     echo Removing Python packages...
echo     if exist "venv\Scripts\python.exe" (
echo         venv\Scripts\python.exe -m pip uninstall -y -r install\requirements.txt
echo     ^) else (
echo         python -m pip uninstall -y -r install\requirements.txt
echo     ^)
echo     echo.
echo     echo Removing desktop shortcut...
echo     del "%%USERPROFILE%%\\Desktop\\KittySploit.lnk" 2^>nul
echo     echo.
echo     echo Removing start scripts...
echo     del start_kittysploit.bat 2^>nul
echo     echo.
echo     echo KittySploit Framework uninstalled successfully!
echo ^) else (
echo     echo Uninstall cancelled.
echo ^)
echo pause
) > uninstall.bat

echo [+] Uninstall script created: uninstall.bat
echo.

REM Create environment setup
echo [*] Creating environment setup...
(
echo #!/usr/bin/env python3
echo # -*- coding: utf-8 -*-
echo.
echo """
echo KittySploit Environment Setup
echo """
echo.
echo import os
echo import sys
echo from pathlib import Path
echo.
echo def setup_environment(^):
echo     """Setup KittySploit environment"""
echo     print("Setting up KittySploit environment..."^)
echo     
echo     # Add current directory to Python path
echo     current_dir = Path(__file__^).parent.absolute(^)
echo     if str(current_dir^) not in sys.path:
echo         sys.path.insert(0, str(current_dir^)^)
echo     
echo     # Set environment variables
echo     os.environ['KITTYSPLOIT_HOME'] = str(current_dir^)
echo     os.environ['KITTYSPLOIT_VERSION'] = '1.0.0'
echo     
echo     print(f"KittySploit home: {current_dir}"^)
echo     print("Environment setup complete!"^)
echo.
echo if __name__ == "__main__":
echo     setup_environment(^)
) > "!PROJECT_ROOT!\env_setup.py"

echo [+] Environment setup created: env_setup.py
echo.


echo  How to start KittySploit:
echo  [*] Double-click 'start_kittysploit.bat'
if !HAS_VENV!==1 (
    echo  [*] Or activate venv and run: python kittyconsole.py
    echo  [*]   Activate with: venv\Scripts\activate.bat
) else (
    echo  [*] Or run: python kittyconsole.py
)

echo To uninstall:
echo  [*] Run: uninstall.bat