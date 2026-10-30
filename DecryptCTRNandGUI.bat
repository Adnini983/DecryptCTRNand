@echo off
rem DecryptCTRNandGUI launcher - requires JRE/JDK 11 or newer (no other dependencies)
rem   Double-click            -> opens the Swing GUI
rem   DecryptCTRNandGUI.bat --cli --nand ... --boot9 ... --otp ... [--cid ...] [--cid-file ...]
rem                             [--mode dev|retail] [--outdir ...] [--force] [--otp-dec] [--show-keys]
cd /d "%~dp0"
if "%~1"=="" (
    start "DecryptCTRNand" javaw -jar "%~dp0java\DecryptCTRNandGUI.jar"
) else (
    java -jar "%~dp0java\DecryptCTRNandGUI.jar" %*
)
