@echo off
REM DecryptCTRNand - Windows BAT launcher
REM Calls PowerShell script with all arguments passed through

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0DecryptCTRNand.ps1" %*
