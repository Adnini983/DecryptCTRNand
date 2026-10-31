@echo off
rem DecryptCTRNandGUI - OPTIONAL convenience launcher (the jar itself is standalone)
rem   The jar is self-contained: double-click java\DecryptCTRNandGUI.jar to open the
rem   Swing GUI (Main-Class in manifest), or run CLI with PS1-identical parameters:
rem   java -jar java\DecryptCTRNandGUI.jar -NandFile ... -Boot9File ... -OtpFile ... ...
rem
rem   Double-click this bat        -> opens the Swing GUI
rem   This bat with arguments      -> passes them through to java -jar (CLI mode)
cd /d "%~dp0"
if "%~1"=="" (
    start "DecryptCTRNand" javaw -jar "%~dp0java\DecryptCTRNandGUI.jar"
) else (
    java -jar "%~dp0java\DecryptCTRNandGUI.jar" %*
)
