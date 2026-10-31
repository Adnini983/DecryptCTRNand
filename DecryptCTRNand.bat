@echo off
REM DecryptCTRNand - Windows BAT launcher (2.0)
REM Calls the PowerShell implementation with all arguments passed through.
REM
REM Parameters (see README.md for details):
REM   -NandFile <sysnand.bin>     -Boot9File <boot9.bin>   -OtpFile <otp.mem>
REM   [-OtpDecrypted]             [-CidHex <32hex> | -CidFile <nand_cid.mem>]
REM   [-OutDir <dir>]             [-Mode dev|retail]        [-Force] [-ShowKeys]
REM
REM Example:
REM   DecryptCTRNand.bat -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem ^
REM                      -CidFile nand_cid.mem -Mode dev -OutDir out

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0DecryptCTRNand.ps1" %*
