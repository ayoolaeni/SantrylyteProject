@echo off
setlocal

cd /d "%~dp0"

echo Stopping SentryLite...
echo.

docker compose down

echo.
echo SentryLite has been stopped. Your data has been kept and will
echo still be there next time you run "Start SentryLite.bat".
echo.
pause
