@echo off
cd /d "%~dp0"
powershell.exe -ExecutionPolicy Bypass -NoExit -File "%~dp0start_siem_local.ps1"
