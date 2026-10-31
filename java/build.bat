@echo off
rem Build DecryptCTRNandGUI.jar (requires JDK 11+; compiles to Java 11 bytecode)
setlocal
cd /d "%~dp0"
if exist classes rmdir /s /q classes
mkdir classes
javac --release 11 -encoding UTF-8 -d classes DecryptCTRNandGUI.java
if errorlevel 1 goto :err
jar cfm DecryptCTRNandGUI.jar MANIFEST.MF -C classes .
if errorlevel 1 goto :err
echo.
echo Built: %~dp0DecryptCTRNandGUI.jar  (pure JDK 11, zero external dependencies)
echo Double-click DecryptCTRNandGUI.jar itself to open the GUI (no launcher bat needed).
exit /b 0
:err
echo BUILD FAILED
exit /b 1
