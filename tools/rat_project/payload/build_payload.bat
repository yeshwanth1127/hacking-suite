@echo off
setlocal enabledelayedexpansion

:: ===== Configuration =====
set PAYLOAD_NAME=dummy_payload

:: ===== Compilation =====
echo [+] Compiling %PAYLOAD_NAME%.dll...
gcc -shared -o ../%PAYLOAD_NAME%.dll ../%PAYLOAD_NAME%.c -Wall
if errorlevel 1 (
    echo [!] DLL Compilation failed.
    pause
    exit /b 1
)

echo.
echo [✓] DLL Build Complete: %PAYLOAD_NAME%.dll created in root directory.
pause
