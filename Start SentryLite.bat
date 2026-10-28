@echo off
setlocal

cd /d "%~dp0"

echo ============================================
echo   Starting SentryLite...
echo ============================================
echo.

docker info >nul 2>&1
if errorlevel 1 (
    echo Docker Desktop does not appear to be running.
    echo.
    echo Please open Docker Desktop from your Start Menu, wait until it
    echo says "Docker Desktop is running", then double-click this file again.
    echo.
    pause
    exit /b 1
)

if not exist ".env" (
    powershell -NoProfile -Command "$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); 'SECRET_KEY=' + [BitConverter]::ToString($b).Replace('-','') | Set-Content -Encoding ascii .env"
)

echo Docker is running. Building and starting SentryLite...
echo (The first time you run this, it can take a few minutes. After that,
echo  it will start in a few seconds.)
echo.

docker compose up -d --build --wait
if errorlevel 1 (
    echo.
    echo ============================================
    echo   Something went wrong starting SentryLite.
    echo ============================================
    echo Please take a screenshot of this window and send it back for help.
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================
echo   SentryLite is running!
echo ============================================
echo.
echo Opening it in your browser now...
echo.
echo   Web address:  http://localhost:5000
echo   Username:     admin
echo   Password:     admin
echo   (you'll be asked to set a new password the first time you log in)
echo.
echo You can close this window - SentryLite will keep running in the
echo background. To stop it later, double-click "Stop SentryLite.bat".
echo.

start "" http://localhost:5000

pause
