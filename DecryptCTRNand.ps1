<#
.SYNOPSIS
    DecryptCTRNand - 3DS NAND Dump Decryptor (Windows Native: PowerShell + .NET)
.DESCRIPTION
    Decrypt 3DS NAND dumps using plaintext boot9 + OTP + eMMC CID.
    Keyinit algorithm ported from pyctr crypto/engine.py (MIT), validated on SPR devkit dump.
.NOTES
    Naming motivation: GodMode9 cannot fully decrypt dev NAND on-device;
    this tool provides PC-side offline decryption as an alternative.
#>

param(
    [Parameter(Mandatory=$true, HelpMessage="NAND dump file path")]
    [string]$NandFile,

    [Parameter(Mandatory=$true, HelpMessage="Plaintext boot9.bin path")]
    [string]$Boot9File,

    [Parameter(Mandatory=$true, HelpMessage="OTP file path (encrypted or decrypted)")]
    [string]$OtpFile,

    [switch]$OtpDecrypted,

    [string]$CidHex,

    [string]$CidFile,

    [string]$OutDir,

    [ValidateSet("dev","retail")]
    [string]$Mode = "dev"
)

$ErrorActionPreference = "Stop"

# === Inline C# crypto helpers ===
Add-Type -TypeDefinition @"
using System;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

public static class NandCrypto {
    public static readonly BigInteger C1 = BigInteger.Parse("1FF9E9AAC5FE0408024591DC5D52768A", NumberStyles.HexNumber);
    public static readonly BigInteger Mask128 = (BigInteger.One << 128) - BigInteger.One;

    public static byte[] ROL128(byte[] input, int n) {
        // input is big-endian 16 bytes
        // Convert to little-endian BigInteger (unsigned)
        byte[] le = new byte[16];
        Array.Copy(input, 0, le, 0, 16);
        Array.Reverse(le);  // big-endian -> little-endian (16 bytes)
        // Add 0x00 at the end (highest position) to force unsigned
        byte[] leUnsigned = new byte[17];
        Array.Copy(le, 0, leUnsigned, 0, 16);
        leUnsigned[16] = 0;
        BigInteger val = new BigInteger(leUnsigned);
        val = ((val << n) | (val >> (128 - n))) & Mask128;
        byte[] result = val.ToByteArray();
        Array.Resize(ref result, 16);
        Array.Reverse(result);  // little-endian -> big-endian
        return result;
    }

    public static byte[] ROR128(byte[] input, int n) {
        return ROL128(input, 128 - n);
    }

    public static byte[] Scramble(byte[] keyX, byte[] keyY) {
        // NormalKey = (((KeyX ROL 2) XOR KeyY) + C1) ROR 41
        byte[] kxRol2 = ROL128(keyX, 2);
        byte[] xor = new byte[16];
        for (int i = 0; i < 16; i++) xor[i] = (byte)(kxRol2[i] ^ keyY[i]);

        // Convert xor to BigInteger (unsigned)
        byte[] xorLe = new byte[16];
        Array.Copy(xor, 0, xorLe, 0, 16);
        Array.Reverse(xorLe);
        byte[] xorLeUnsigned = new byte[17];
        Array.Copy(xorLe, 0, xorLeUnsigned, 0, 16);
        xorLeUnsigned[16] = 0;
        BigInteger xorInt = new BigInteger(xorLeUnsigned);
        BigInteger sumInt = (xorInt + C1) & Mask128;

        byte[] sumBytes = sumInt.ToByteArray();
        Array.Resize(ref sumBytes, 16);
        Array.Reverse(sumBytes);

        return ROR128(sumBytes, 41);
    }

    public static byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] data) {
        using (Aes aes = Aes.Create()) {
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.KeySize = 128;
            aes.Key = key;
            aes.IV = iv;
            using (ICryptoTransform dec = aes.CreateDecryptor()) {
                return dec.TransformFinalBlock(data, 0, data.Length);
            }
        }
    }

    public static byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] data) {
        using (Aes aes = Aes.Create()) {
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.KeySize = 128;
            aes.Key = key;
            aes.IV = iv;
            using (ICryptoTransform enc = aes.CreateEncryptor()) {
                return enc.TransformFinalBlock(data, 0, data.Length);
            }
        }
    }

    public static byte[] AesCtrDecrypt(byte[] key, byte[] counter, byte[] data) {
        using (Aes aes = Aes.Create()) {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.KeySize = 128;
            aes.Key = key;
            int numBlocks = (data.Length + 15) / 16;
            byte[] keystream = new byte[numBlocks * 16];

            byte[] ctr = new byte[16];
            Array.Copy(counter, 0, ctr, 0, 16);

            using (ICryptoTransform enc = aes.CreateEncryptor()) {
                for (int i = 0; i < numBlocks; i++) {
                    byte[] block = enc.TransformFinalBlock(ctr, 0, 16);
                    Array.Copy(block, 0, keystream, i*16, 16);
                    for (int j = 15; j >= 0; j--) {
                        ctr[j]++;
                        if (ctr[j] != 0) break;
                    }
                }
            }

            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) {
                result[i] = (byte)(data[i] ^ keystream[i]);
            }
            return result;
        }
    }

    public static byte[] Sha256(byte[] data) {
        using (SHA256 sha = SHA256.Create()) {
            return sha.ComputeHash(data);
        }
    }

    public static byte[] AddCounter(byte[] nonce, long blockOffset) {
        byte[] le = new byte[16];
        Array.Copy(nonce, 0, le, 0, 16);
        Array.Reverse(le);
        byte[] leUnsigned = new byte[17];
        Array.Copy(le, 0, leUnsigned, 0, 16);
        leUnsigned[16] = 0;
        BigInteger val = new BigInteger(leUnsigned);
        val = (val + blockOffset) & Mask128;
        byte[] result = val.ToByteArray();
        Array.Resize(ref result, 16);
        Array.Reverse(result);
        return result;
    }
}
"@ -ReferencedAssemblies System.Numerics

# === Helpers ===
function BytesToHex($bytes) {
    return ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""
}

function SubBytes($src, $offset, $length) {
    $dst = New-Object byte[] $length
    [Array]::Copy($src, $offset, $dst, 0, $length)
    return $dst
}

# === Main ===
Write-Host "=== DecryptCTRNand ===" -ForegroundColor Cyan
Write-Host "NAND: $NandFile"
Write-Host "boot9: $Boot9File"
Write-Host "OTP: $OtpFile"
Write-Host "Mode: $Mode"

# Read inputs
$boot9Full = [System.IO.File]::ReadAllBytes($Boot9File)
$otpRaw = [System.IO.File]::ReadAllBytes($OtpFile)

# Step 1: OTP
$isDev = ($Mode -eq "dev")

if ($OtpDecrypted) {
    Write-Host "`n[*] Using pre-decrypted OTP"
    $otpPlain = $otpRaw
} else {
    Write-Host "`n[*] Decrypting OTP..."

    # dev: nk@0xD700, iv@0xD710; retail: nk@0xD6E0, iv@0xD6F0
    $nkOff = if ($isDev) { 0xD700 } else { 0xD6E0 }
    $ivOff = if ($isDev) { 0xD710 } else { 0xD6F0 }

    $nk = SubBytes $boot9Full $nkOff 16
    $iv = SubBytes $boot9Full $ivOff 16

    $plain = [NandCrypto]::AesCbcDecrypt($nk, $iv, $otpRaw)

    # Check magic (DEADB00F little-endian)
    if (-not ($plain[0] -eq 0x0F -and $plain[1] -eq 0xB0 -and $plain[2] -eq 0xAD -and $plain[3] -eq 0xDE)) {
        throw "OTP magic mismatch. Decryption failed."
    }

    # Verify SHA256
    $plainHead = SubBytes $plain 0 0xE0
    $hash = [NandCrypto]::Sha256($plainHead)
    $tail = SubBytes $plain 0xE0 0x20

    $match = $true
    for ($i = 0; $i -lt 32; $i++) {
        if ($hash[$i] -ne $tail[$i]) { $match = $false; break }
    }

    if (-not $match) {
        throw "OTP SHA256 integrity check failed."
    }

    Write-Host "[+] OTP decrypted successfully ($Mode)" -ForegroundColor Green
    Write-Host "    Dev flag: 0x$($plain[0x19].ToString('X2'))"
    $otpPlain = $plain
}

# Step 2: CID
if ($CidFile) {
    $cid = [System.IO.File]::ReadAllBytes($CidFile)
    Write-Host "`n[+] CID loaded from file"
} elseif ($CidHex) {
    $cid = New-Object byte[] ($CidHex.Length / 2)
    for ($i = 0; $i -lt $CidHex.Length; $i += 2) {
        $cid[$i/2] = [Convert]::ToByte($CidHex.Substring($i, 2), 16)
    }
    Write-Host "`n[+] CID from hex"
} else {
    Write-Host "`n[!] No CID provided." -ForegroundColor Red
    Write-Host "    NAND AES-CTR nonce = SHA256(CID)[:16], 128-bit, cannot brute-force." -ForegroundColor Red
    Write-Host "    Please provide -CidFile or -CidHex." -ForegroundColor Red
    exit 1
}

# Step 3: NCSD parse
Write-Host "`n[*] Parsing NCSD header..."
$nandFs = [System.IO.File]::OpenRead($NandFile)
$ncsdHeader = New-Object byte[] 0x200
$nandFs.Read($ncsdHeader, 0, 0x200) | Out-Null

$magic = [System.Text.Encoding]::ASCII.GetString($ncsdHeader, 0x100, 4)
if ($magic -ne "NCSD") {
    $nandFs.Close()
    throw "NCSD magic not found at 0x100. Got: $magic"
}

Write-Host "[+] NCSD magic found at +0x100" -ForegroundColor Green

$partitions = @()
for ($i = 0; $i -lt 8; $i++) {
    $fstype = $ncsdHeader[0x110 + $i]
    $crypttype = $ncsdHeader[0x118 + $i]
    $offset = [BitConverter]::ToUInt32($ncsdHeader, 0x120 + $i*8)
    $size = [BitConverter]::ToUInt32($ncsdHeader, 0x120 + $i*8 + 4)

    if ($fstype -ne 0 -or $crypttype -ne 0) {
        $absOffset = $offset * 0x200
        $absSize = $size * 0x200

        # Determine AES slot
        $slot = 0
        if ($crypttype -eq 1) { $slot = 0x03 }
        elseif ($crypttype -eq 2) {
            if ($fstype -eq 4) { $slot = 0x07 }
            else { $slot = 0x06 }
            # Old3DS CTRNAND: crypttype=2, fstype=1, byte offset > 0xB00000
            if ($fstype -eq 1 -and $absOffset -gt 0xB00000) { $slot = 0x04 }
        }
        elseif ($crypttype -eq 3) { $slot = 0x05 }
        else { $slot = 0x04 }

        $partitions += @{
            Index = $i
            FSType = $fstype
            CryptType = $crypttype
            Offset = $absOffset
            Size = $absSize
            Slot = $slot
        }

        Write-Host "    Partition $i : slot=0x$($slot.ToString('X2')) offset=0x$($absOffset.ToString('X8')) size=0x$($absSize.ToString('X8'))"
    }
}

# Step 4: Keyinit (ported from pyctr, validated on SPR)
Write-Host "`n[*] Keyinit (OTP + boot9 -> console-unique normalKeys)..."

# 64KB boot9 -> take last 32KB
if ($boot9Full.Length -eq 0x10000) {
    $b9 = SubBytes $boot9Full 0x8000 0x8000
} else {
    $b9 = $boot9Full
}

# keyblob offset: retail=0x5860, dev=0x5C60
$keyblobOffset = if ($isDev) { 0x5C60 } else { 0x5860 }

# b9_extdata_keygen = first 0x200 bytes of keyblob
$b9ExtdataKeygen = SubBytes $b9 $keyblobOffset 0x200

# b9_extdata_otp = first 0x24 bytes (CRITICAL: 0x24, not 0x20!)
$b9ExtdataOtp = SubBytes $b9ExtdataKeygen 0 0x24

# console_key_xy = SHA256(OTP_dec[0x90:0xAC] + b9_extdata_otp)
$otpSeed = SubBytes $otpPlain 0x90 0x1C
$seedPlusOtp = New-Object byte[] ($otpSeed.Length + $b9ExtdataOtp.Length)
[Array]::Copy($otpSeed, 0, $seedPlusOtp, 0, $otpSeed.Length)
[Array]::Copy($b9ExtdataOtp, 0, $seedPlusOtp, $otpSeed.Length, $b9ExtdataOtp.Length)
$consoleKeyXy = [NandCrypto]::Sha256($seedPlusOtp)

# slot0x3F KeyX / KeyY -> scramble to normalKey
$slot3fKeyX = SubBytes $consoleKeyXy 0 16
$slot3fKeyY = SubBytes $consoleKeyXy 16 16
$slot3fNormalKey = [NandCrypto]::Scramble($slot3fKeyX, $slot3fKeyY)

Write-Host "    slot0x3F normalKey derived" -ForegroundColor DarkGray

# gen() function: AES-CBC ENCRYPT (not decrypt!)
$script:extdataOff = 0
function Gen($n) {
    $script:extdataOff += 36
    $iv = SubBytes $script:b9ExtdataKeygen $script:extdataOff 16
    $script:extdataOff += 16
    $data = SubBytes $script:b9ExtdataKeygen $script:extdataOff 64
    $encrypted = [NandCrypto]::AesCbcEncrypt($script:slot3fNormalKey, $iv, $data)
    $script:extdataOff += $n
    return $encrypted
}

$a = Gen 64
$slot04_07_KeyX = SubBytes $a 0 16

# KeyY from keyblob at offset 0x1F0 (slots 0x04, 0x06, 0x07)
# Note: slot0x05 (New3DS CTRNAND) uses a FIXED global KeyY, not from keyblob
# Fixed CTRNANDNew KeyY: 0x4D804F4E9990194613A204AC584460BE (same for dev/retail)
$keyblob = SubBytes $b9 $keyblobOffset 0x400
$fixedKeyY_CtrnandNew = [byte[]]::new(16)
$hex = "4D804F4E9990194613A204AC584460BE"
for ($i = 0; $i -lt 16; $i++) {
    $fixedKeyY_CtrnandNew[$i] = [Convert]::ToByte($hex.Substring($i*2, 2), 16)
}

$normalKeys = @{}
# slot0x04: keyblob[0x1F0]
$keyy_04 = SubBytes $keyblob 0x1F0 16
$normalKeys[0x04] = [NandCrypto]::Scramble($slot04_07_KeyX, $keyy_04)
# slot0x05: FIXED KeyY (New3DS CTRNAND)
$normalKeys[0x05] = [NandCrypto]::Scramble($slot04_07_KeyX, $fixedKeyY_CtrnandNew)
# slot0x06: keyblob[0x210]
$keyy_06 = SubBytes $keyblob 0x210 16
$normalKeys[0x06] = [NandCrypto]::Scramble($slot04_07_KeyX, $keyy_06)
# slot0x07: keyblob[0x220]
$keyy_07 = SubBytes $keyblob 0x220 16
$normalKeys[0x07] = [NandCrypto]::Scramble($slot04_07_KeyX, $keyy_07)

Write-Host "`n[+] Derived normalKeys:" -ForegroundColor Green
foreach ($slot in ($normalKeys.Keys | Sort-Object)) {
    Write-Host "    slot 0x$($slot.ToString('X2')): $(BytesToHex $normalKeys[$slot])"
}

# Step 5: Derive nonce
$nonce = [NandCrypto]::Sha256($cid)[0..15]
Write-Host "`n[+] CTR nonce (SHA256(CID)[:16]): $(BytesToHex $nonce)"

# Step 6: Decrypt partitions (if OutDir specified)
if ($OutDir) {
    Write-Host "`n[*] Decrypting partitions to: $OutDir" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

    foreach ($p in $partitions) {
        $slot = $p.Slot
        if (-not $normalKeys.ContainsKey($slot)) {
            Write-Host "    Partition $($p.Index): slot 0x$($slot.ToString('X2')) not derived, skipping" -ForegroundColor Yellow
            continue
        }

        $nk = $normalKeys[$slot]
        $outFile = Join-Path $OutDir "partition_$($p.Index)_slot$($slot.ToString('X2')).bin"

        Write-Host "    Partition $($p.Index) (slot 0x$($slot.ToString('X2')))... " -NoNewline

        $nandFs.Seek($p.Offset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $outFs = [System.IO.File]::Create($outFile)

        $remaining = $p.Size
        $chunkSize = 0x100000
        $buf = New-Object byte[] $chunkSize

        while ($remaining -gt 0) {
            $toRead = [Math]::Min($chunkSize, $remaining)
            $read = $nandFs.Read($buf, 0, $toRead)
            if ($read -eq 0) { break }

            $absOff = $p.Offset + ($p.Size - $remaining)
            $blockOffset = [long]($absOff / 16)
            $counter = [NandCrypto]::AddCounter($nonce, $blockOffset)

            $decBuf = $buf[0..($read-1)]
            $decrypted = [NandCrypto]::AesCtrDecrypt($nk, $counter, $decBuf)
            $outFs.Write($decrypted, 0, $decrypted.Length)

            $remaining -= $read
        }

        $outFs.Close()
        Write-Host "saved ($([Math]::Round($p.Size / 1MB, 1)) MB)" -ForegroundColor Green
    }
}

$nandFs.Close()

# === Summary ===
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "OTP: decrypted OK ($Mode)"
Write-Host "NCSD: parsed, $($partitions.Count) partitions OK"
Write-Host "CID: loaded OK"
Write-Host "Keyinit: completed OK (slots 0x04-0x07)"
Write-Host "nonce: derived OK"
if ($OutDir) {
    Write-Host "Partitions: decrypted to $OutDir"
} else {
    Write-Host "`n[*] No -OutDir specified, keys derived but partitions not written to disk." -ForegroundColor Yellow
}
