@echo off
rem Quick read-only inspection (a few minutes). Asks for admin, writes to this drive's reports folder.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Inspect-Windows.ps1"
echo.
pause
