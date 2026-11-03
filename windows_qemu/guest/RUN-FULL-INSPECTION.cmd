@echo off
rem Full inspection: adds chkdsk online scan, sfc /verifyonly and DISM /ScanHealth (20-40 min). Asks for admin, writes to this drive's reports folder.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Inspect-Windows.ps1" -Full
echo.
pause
