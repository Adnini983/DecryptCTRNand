<#
.SYNOPSIS
    DecryptCTRNand 2.0 - 3DS NAND Dump Decryptor (Windows Native: PowerShell + .NET)

.DESCRIPTION
    Decrypt 3DS NAND dumps using plaintext boot9 + OTP + eMMC CID.
    Keyinit algorithm ported from pyctr crypto/engine.py (MIT), validated on SPR devkit dump.

    v2.0 changes (correctness / input validation / output validation):
      * AES-CTR now builds the full counter stream and encrypts it with a single
        TransformBlock call (no per-block TransformFinalBlock in a loop).
      * ReadExactly loop: short reads are re-read until the requested length is
        filled; a truncated NAND now aborts instead of silently reporting success.
      * Strict input length validation (boot9 / OTP / CID / -CidHex / NAND).
      * OTP plaintext is ALWAYS validated (DEADB00F magic + SHA256 + length +
        dev flag vs -Mode), including the -OtpDecrypted path.
      * NCSD partition table boundary / overlap checks; unknown crypt/fs types are
        refused instead of defaulting to a guessed AES slot.
      * Structural output checks: MBR 55AA (CTRNAND), FIRM magic (firm partitions),
        actual written byte count, per-partition SHA-256 record.
      * Overwrite protection: refuses to overwrite existing outputs unless -Force.
      * Keys written to a .tmp file first and renamed only after checks pass.
      * normalKeys / CID are hidden by default; use -ShowKeys to display.
      * try/finally resource cleanup.

.NOTES
    Naming motivation: GodMode9 cannot fully decrypt dev NAND on-device;
    this tool provides PC-side offline decryption as an alternative.

    Structural checks (MBR 55AA / FIRM magic / SHA-256) are sanity checks only.
    AES-CTR provides no integrity/authentication: they do not prove the output
    is authentic, they only catch obviously wrong keys/offsets/truncation.
#>

param(
    [Parameter(Mandatory=$true, HelpMessage="NAND dump file path")]
    [string]$NandFile,

    [Parameter(Mandatory=$true, HelpMessage="Plaintext boot9.bin path (64KB GM9 dump or 32KB prot-only)")]
    [string]$Boot9File,

    [Parameter(Mandatory=$true, HelpMessage="OTP file path (encrypted or decrypted)")]
    [string]$OtpFile,

    [switch]$OtpDecrypted,

    [string]$CidHex,

    [string]$CidFile,

    [string]$OutDir,

    [ValidateSet("dev","retail")]
    [string]$Mode = "dev",

    # Allow overwriting existing output files
    [switch]$Force,

    # Display derived normalKeys (hidden by default for security)
    [switch]$ShowKeys
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
        byte[] le = new byte[16];
        Array.Copy(input, 0, le, 0, 16);
        Array.Reverse(le);
        byte[] leUnsigned = new byte[17];
        Array.Copy(le, 0, leUnsigned, 0, 16);
        leUnsigned[16] = 0;
        BigInteger val = new BigInteger(leUnsigned);
        val = ((val << n) | (val >> (128 - n))) & Mask128;
        byte[] result = val.ToByteArray();
        Array.Resize(ref result, 16);
        Array.Reverse(result);
        return result;
    }

    public static byte[] ROR128(byte[] input, int n) {
        return ROL128(input, 128 - n);
    }

    public static byte[] Scramble(byte[] keyX, byte[] keyY) {
        // NormalKey = (((KeyX ROL 2) XOR KeyY) + C1) ROR 41   (== pyctr rol(..., 87))
        byte[] kxRol2 = ROL128(keyX, 2);
        byte[] xor = new byte[16];
        for (int i = 0; i < 16; i++) xor[i] = (byte)(kxRol2[i] ^ keyY[i]);
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

    // AES-CTR via full counter-stream generation + one TransformBlock call.
    // Accepts data of any length (final partial block handled by XOR truncation).
    public static byte[] AesCtrDecrypt(byte[] key, byte[] counter, byte[] data) {
        using (Aes aes = Aes.Create()) {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.KeySize = 128;
            aes.Key = key;

            int numBlocks = (data.Length + 15) / 16;
            byte[] ctrStream = new byte[numBlocks * 16];
            byte[] ctr = new byte[16];
            Array.Copy(counter, 0, ctr, 0, 16);
            for (int i = 0; i < numBlocks; i++) {
                Array.Copy(ctr, 0, ctrStream, i * 16, 16);
                for (int j = 15; j >= 0; j--) {
                    ctr[j]++;
                    if (ctr[j] != 0) break;
                }
            }

            byte[] keystream = new byte[numBlocks * 16];
            using (ICryptoTransform enc = aes.CreateEncryptor()) {
                enc.TransformBlock(ctrStream, 0, ctrStream.Length, keystream, 0);
            }

            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) {
                result[i] = (byte)(data[i] ^ keystream[i]);
            }
            return result;
        }
    }

    // AES-ECB single-block encrypt (used for the misaligned TWL MBR head).
    public static byte[] AesEcbBlock(byte[] key, byte[] block) {
        using (Aes aes = Aes.Create()) {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.KeySize = 128;
            aes.Key = key;
            using (ICryptoTransform enc = aes.CreateEncryptor()) {
                return enc.TransformFinalBlock(block, 0, 16);
            }
        }
    }

    public static byte[] Sha256(byte[] data) {
        using (SHA256 sha = SHA256.Create()) {
            return sha.ComputeHash(data);
        }
    }

    public static byte[] Sha1(byte[] data) {
        using (SHA1 sha = SHA1.Create()) {
            return sha.ComputeHash(data);
        }
    }

    // TWL/DSi keyscrambler: NormalKey = ROL42(((keyX_LE ^ keyY_LE) + TwlConst) mod 2^128), BE output.
    public static readonly BigInteger TwlConst = BigInteger.Parse("FFFEFB4E295902582A680F5F1A4F3E79", NumberStyles.HexNumber);

    public static byte[] ScrambleTwl(byte[] keyX, byte[] keyY) {
        // keyX/keyY are the stored LE u32 arrays; interpret them as little-endian
        // integers directly (the old code Array.Reverse'd them first, which is a
        // big-endian interpretation and produced wrong TWL keys).
        byte[] kxUnsigned = new byte[17];
        Array.Copy(keyX, 0, kxUnsigned, 0, 16);
        kxUnsigned[16] = 0;
        byte[] kyUnsigned = new byte[17];
        Array.Copy(keyY, 0, kyUnsigned, 0, 16);
        kyUnsigned[16] = 0;
        BigInteger kxInt = new BigInteger(kxUnsigned);
        BigInteger kyInt = new BigInteger(kyUnsigned);
        BigInteger t = (kxInt ^ kyInt) + TwlConst;
        t = t & Mask128;
        t = ((t << 42) | (t >> 86)) & Mask128;
        byte[] result = t.ToByteArray();
        Array.Resize(ref result, 16);
        Array.Reverse(result);
        return result;
    }

    // TWL CTR: keystream block = AES-ECB(key, BE128(counter)), XORed byte-reversed per block
    // (the DSi AES engine processes blocks in reversed byte order; pyctr _TWLCryptoWrapper).
    public static byte[] TwlCtrCrypt(byte[] key, byte[] counter, byte[] data) {
        using (Aes aes = Aes.Create()) {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.KeySize = 128;
            aes.Key = key;

            int numBlocks = (data.Length + 15) / 16;
            byte[] ctrStream = new byte[numBlocks * 16];
            byte[] ctr = new byte[16];
            Array.Copy(counter, 0, ctr, 0, 16);
            for (int i = 0; i < numBlocks; i++) {
                Array.Copy(ctr, 0, ctrStream, i * 16, 16);
                for (int j = 15; j >= 0; j--) {
                    ctr[j]++;
                    if (ctr[j] != 0) break;
                }
            }

            byte[] keystream = new byte[numBlocks * 16];
            using (ICryptoTransform enc = aes.CreateEncryptor()) {
                enc.TransformBlock(ctrStream, 0, ctrStream.Length, keystream, 0);
            }

            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) {
                int blockBase = (i / 16) * 16;
                int rev = blockBase + 15 - (i % 16);
                result[i] = (byte)(data[i] ^ keystream[rev]);
            }
            return result;
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

# ReadExactly: keeps reading until $count bytes are filled or EOF.
# Returns the number of bytes actually read (may be < $count only at EOF).
function ReadExactly($stream, $buffer, $offset, $count) {
    $total = 0
    while ($total -lt $count) {
        $read = $stream.Read($buffer, $offset + $total, $count - $total)
        if ($read -le 0) { break }
        $total += $read
    }
    return $total
}

# Commit-TempFile: atomically publish a fully-verified .tmp file as the final
# output. The old output file is NEVER deleted in advance - it survives any
# mid-decrypt failure and is only replaced once the new file has been written
# and validated. On NTFS, [IO.File]::Replace is atomic; if the filesystem does
# not support it we fall back to a backup-and-swap that still restores the old
# file if the swap itself fails.
function Commit-TempFile([string]$tmpFile, [string]$outFile) {
    if (Test-Path -LiteralPath $outFile -PathType Leaf) {
        try {
            [System.IO.File]::Replace($tmpFile, $outFile, $null)
        } catch {
            # Non-atomic fallback: move the old file aside, swap in the new one,
            # and roll the old file back if the swap fails.
            $bak = "$outFile.bak"
            if (Test-Path -LiteralPath $bak -PathType Leaf) { Remove-Item -LiteralPath $bak -Force }
            [System.IO.File]::Move($outFile, $bak)
            try {
                [System.IO.File]::Move($tmpFile, $outFile)
                Remove-Item -LiteralPath $bak -Force
            } catch {
                [System.IO.File]::Move($bak, $outFile)
                throw
            }
        }
    } else {
        [System.IO.File]::Move($tmpFile, $outFile)
    }
}

# Streaming SHA-256 of a file (1MB chunks), returns hex string.
function Get-FileSha256([string]$path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = [System.IO.File]::OpenRead($path)
        try {
            $buf = New-Object byte[] 0x100000
            while ($true) {
                $read = $fs.Read($buf, 0, $buf.Length)
                if ($read -le 0) { break }
                if ($read -eq $buf.Length) {
                    $null = $sha.TransformBlock($buf, 0, $read, $null, 0)
                } else {
                    $null = $sha.TransformFinalBlock($buf, 0, $read)
                    break
                }
            }
            if (-not $sha.Hash) {
                $null = $sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
            }
            return (BytesToHex $sha.Hash)
        } finally {
            $fs.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
}

# === TWL (slot 0x03) helpers ===
# TWL keyX = [CustId_lo, 0xEE7A4B1E("dev")|"NINT", 0xAF42C08B("dev")|"ENDO", CustId_hi] as LE u32s.
# dev   : CustId = RAW (encrypted) OTP[0:8] little-endian  (otp_dec is WRONG here)
# retail: CustId = OTP_plain[8:16] ^ 0x08C267B7B358A6AF | 0x80000000
function Get-TwlKey([byte[]]$otpEnc, [byte[]]$otpPlain, [bool]$isDev) {
    $keyyHex = if ($isDev) { "AABF76F17AB8E86697646A260500A0E1" } else { "76DCB90AD3C44DBD1DDD2D200500A0E1" }
    $keyy = [byte[]]::new(16)
    for ($i = 0; $i -lt 16; $i++) { $keyy[$i] = [Convert]::ToByte($keyyHex.Substring($i*2, 2), 16) }

    $keyx = [byte[]]::new(16)
    if ($isDev) {
        $lo = [long][BitConverter]::ToUInt32($otpEnc, 0)
        $hi = [long][BitConverter]::ToUInt32($otpEnc, 4)
        [BitConverter]::GetBytes([uint32]$lo).CopyTo($keyx, 0)
        # NOTE: PS5.1 parses hex literals > 0x7FFFFFFF as negative [int]; cast via
        # [Convert]::ToUInt32(hex-string) to get the intended u32 constant.
        [BitConverter]::GetBytes([uint32][Convert]::ToUInt32("EE7A4B1E", 16)).CopyTo($keyx, 4)
        [BitConverter]::GetBytes([uint32][Convert]::ToUInt32("AF42C08B", 16)).CopyTo($keyx, 8)
        [BitConverter]::GetBytes([uint32]$hi).CopyTo($keyx, 12)
    } else {
        $lo = [long][BitConverter]::ToUInt32($otpPlain, 8)
        $hi = [long][BitConverter]::ToUInt32($otpPlain, 12)
        # PS5.1 parses hex literals > 0x7FFFFFFF as negative [int]; use decimal
        # / [Convert]::ToUInt32 so all arithmetic stays positive [long].
        $lo = ($lo -bxor [long][Convert]::ToUInt32("B358A6AF", 16)) -bor [long]2147483648
        $lo = $lo -band [long]4294967295
        $hi = ($hi -bxor [long][Convert]::ToUInt32("08C267B7", 16)) -band [long]4294967295
        [BitConverter]::GetBytes([uint32]$lo).CopyTo($keyx, 0)
        [BitConverter]::GetBytes([uint32][Convert]::ToUInt32("544E494E", 16)).CopyTo($keyx, 4)
        [BitConverter]::GetBytes([uint32][Convert]::ToUInt32("4F444E45", 16)).CopyTo($keyx, 8)
        [BitConverter]::GetBytes([uint32]$hi).CopyTo($keyx, 12)
    }
    return [NandCrypto]::ScrambleTwl($keyx, $keyy)
}

# TWL nonce = SHA1(CID)[:16], byte-reversed (BE128 of the LE128 integer).
function Get-TwlNonce([byte[]]$cid) {
    $sha1 = [NandCrypto]::Sha1($cid)
    $nonce = [byte[]]::new(16)
    for ($i = 0; $i -lt 16; $i++) { $nonce[$i] = $sha1[15 - $i] }
    return $nonce
}

# Decrypt a TWL NAND partition (NCSD p0, crypttype=0x01, slot 0x03).
# Only two ranges are AES-encrypted on the TWL region:
#   [0x1BE:0x200)  - MBR partition table + boot signature
#   [0x12E00:end)  - twln (FAT16) + twlp (FAT12) + remainder
# Everything else (NCSD header/signature, DSi stage2 area) is copied raw.
function Out-TwlPartition($nandFs, $p, $twlKey, $twlNonce, $OutDir, $Force) {
    $index = $p.Index
    $outFile = Join-Path $OutDir "partition_${index}_slot03.bin"
    $tmpFile = "$outFile.tmp"

    if (Test-Path -LiteralPath $outFile -PathType Leaf) {
        if (-not $Force) { throw "Output already exists: $outFile . Re-run with -Force to overwrite." }
        # -Force: the old file is NOT removed here. It is replaced atomically at
        # commit time only after the new file passed every check (see Commit-TempFile).
    }
    if (Test-Path -LiteralPath $tmpFile -PathType Leaf) {
        Remove-Item -LiteralPath $tmpFile -Force
    }

    Write-Host "    Partition $index (slot 0x03, TWL)... " -NoNewline

    $start = [long]$p.Offset
    $end = $start + [long]$p.Size
    $mbrStart = 0x1BE
    $fatStart = 0x12E00
    $encRanges = @(
        @( $mbrStart, [Math]::Min(0x200, $end) ),
        @( [Math]::Max($fatStart, $start), $end )
    )

    $outFs = $null
    try {
        $outFs = [System.IO.File]::Create($tmpFile)
        $chunkSize = 0x100000
        $buf = New-Object byte[] $chunkSize
        $written = 0L
        $pos = $start
        # NCSD parsing may have advanced the stream; rewind to the partition start.
        $nandFs.Seek($start, [System.IO.SeekOrigin]::Begin) | Out-Null

        foreach ($range in $encRanges) {
            $es = [long]$range[0]
            $ee = [long]$range[1]
            if ($es -ge $ee) { continue }
            # raw copy [pos, es)
            while ($pos -lt $es) {
                $toRead = [Math]::Min($chunkSize, $es - $pos)
                $read = ReadExactly $nandFs $buf 0 $toRead
                if ($read -lt $toRead) { throw "Partition $index : NAND truncated (raw range)" }
                $outFs.Write($buf, 0, $read)
                $written += $read
                $pos += $read
            }
            # decrypt [es, ee) - counter is per ABSOLUTE 16-byte block: nonce + (abs >> 4).
            # A range may start mid-block (0x1BE), so handle the partial head first.
            while ($pos -lt $ee) {
                if (($pos -band 15) -ne 0) {
                    $headLen = [Math]::Min(16 - ($pos -band 15), $ee - $pos)
                    $read = ReadExactly $nandFs $buf 0 $headLen
                    if ($read -lt $headLen) { throw "Partition $index : NAND truncated (TWL head)" }
                    $blockBase = $pos -band (-16)
                    $blockCounter = [NandCrypto]::AddCounter($twlNonce, [long]($blockBase / 16))
                    $ks = [NandCrypto]::AesEcbBlock($twlKey, $blockCounter)
                    $rel = [int]($pos - $blockBase)
                    $decHead = New-Object byte[] $headLen
                    for ($j = 0; $j -lt $headLen; $j++) {
                        $decHead[$j] = [byte]($buf[$j] -bxor $ks[15 - ($rel + $j)])
                    }
                    $outFs.Write($decHead, 0, $headLen)
                    $written += $headLen
                    $pos += $headLen
                    continue
                }
                $toRead = [Math]::Min($chunkSize, $ee - $pos)
                $read = ReadExactly $nandFs $buf 0 $toRead
                if ($read -lt $toRead) { throw "Partition $index : NAND truncated (TWL range)" }
                $decBuf = $buf[0..($read-1)]
                $counter = [NandCrypto]::AddCounter($twlNonce, [long]($pos / 16))
                $decrypted = [NandCrypto]::TwlCtrCrypt($twlKey, $counter, $decBuf)
                $outFs.Write($decrypted, 0, $decrypted.Length)
                $written += $decrypted.Length
                $pos += $read
            }
        }
        # tail raw copy
        while ($pos -lt $end) {
            $toRead = [Math]::Min($chunkSize, $end - $pos)
            $read = ReadExactly $nandFs $buf 0 $toRead
            if ($read -lt $toRead) { throw "Partition $index : NAND truncated (tail range)" }
            $outFs.Write($buf, 0, $read)
            $written += $read
            $pos += $read
        }

        if ($written -ne $p.Size) {
            throw "Partition $index : wrote $written bytes but expected $($p.Size) (incomplete output)"
        }

        $outFs.Flush()
        $outFs.Dispose()
        $outFs = $null

        # ---- TWL structural checks (sanity only; AES-CTR is not authenticated) ----
        $mbr = New-Object byte[] 0x42
        $hfs = [System.IO.File]::OpenRead($tmpFile)
        try {
            $null = $hfs.Seek(0x1BE, [System.IO.SeekOrigin]::Begin)
            $hr = ReadExactly $hfs $mbr 0 0x42
        } finally { $hfs.Dispose() }
        if ($hr -lt 0x42) { throw "Partition $index : output too short for TWL MBR checks" }

        $mbrSigOk = ($mbr[0x40] -eq 0x55 -and $mbr[0x41] -eq 0xAA)   # 0x1FE
        $blk1dHex = BytesToHex (SubBytes $mbr 0x12 16)
        $blk1dOk = ($blk1dHex -eq "8E400601A0C38D800400B30501000000")

        $fatSigOk = $true
        $oemOk = $true
        $oem = ""
        if ($p.Size -gt 0x12E00 + 0x200) {
            # twln FAT boot sector only exists if the TWL region actually covers it
            $fat = New-Object byte[] 0x200
            $hfs2 = [System.IO.File]::OpenRead($tmpFile)
            try {
                $null = $hfs2.Seek(0x12E00, [System.IO.SeekOrigin]::Begin)
                $fr = ReadExactly $hfs2 $fat 0 0x200
            } finally { $hfs2.Dispose() }
            if ($fr -lt 0x200) { throw "Partition $index : TWL region too small for twln boot check" }
            $fatSigOk = ($fat[0x1FE] -eq 0x55 -and $fat[0x1FF] -eq 0xAA)
            $oem = [System.Text.Encoding]::ASCII.GetString($fat, 0x03, 8)
            $oemOk = ($oem -eq "TWL     ")   # FAT boot sector OEM label (8 bytes)
        }

        $notes = @()
        if (-not $mbrSigOk) {
            if (Test-Path -LiteralPath $tmpFile) { Remove-Item -LiteralPath $tmpFile -Force }
            throw "Partition $index : TWL MBR 55AA missing (wrong key/OTP?)"
        }
        $notes += "MBR 55AA OK"
        if (-not $blk1dOk) {
            if (Test-Path -LiteralPath $tmpFile) { Remove-Item -LiteralPath $tmpFile -Force }
            throw "Partition $index : TWL block 0x1D anchor mismatch (wrong key/OTP?)"
        }
        $notes += "blk0x1D anchor OK"
        if (-not $fatSigOk -or -not $oemOk) {
            if (Test-Path -LiteralPath $tmpFile) { Remove-Item -LiteralPath $tmpFile -Force }
            throw "Partition $index : twln FAT boot 55AA missing or OEM != 'TWL     ' (got '$oem', wrong offset?)"
        }
        if ($p.Size -gt 0x12E00 + 0x200) {
            $notes += "twln boot 55AA + OEM 'TWL     ' OK"
        } else {
            $notes += "twln boot check skipped (partition too small)"
        }

        $shaHex = Get-FileSha256 $tmpFile
        Commit-TempFile $tmpFile $outFile

        Write-Host "saved ($([Math]::Round($p.Size / 1MB, 1)) MB, wrote $written bytes, $($notes -join ', '))" -ForegroundColor Green
        Write-Host "        SHA-256: $shaHex" -ForegroundColor DarkGray
    } finally {
        if ($outFs) { $outFs.Dispose() }
        if (Test-Path -LiteralPath $tmpFile) { Remove-Item -LiteralPath $tmpFile -Force }
    }
}

# Unified OTP plaintext validation: length + DEADB00F magic + SHA256 + dev flag vs Mode.
function Assert-ValidOtpPlain([byte[]]$plain, [string]$mode, [string]$sourceDesc) {
    if ($plain.Length -ne 0x100) {
        throw "OTP ${sourceDesc}: expected exactly 0x100 (256) bytes, got $($plain.Length)"
    }
    if (-not ($plain[0] -eq 0x0F -and $plain[1] -eq 0xB0 -and $plain[2] -eq 0xAD -and $plain[3] -eq 0xDE)) {
        throw "OTP ${sourceDesc}: DEADB00F magic not found. Not a valid (decrypted) OTP, or wrong mode key."
    }
    $head = SubBytes $plain 0 0xE0
    $hash = [NandCrypto]::Sha256($head)
    $tail = SubBytes $plain 0xE0 0x20
    $match = $true
    for ($i = 0; $i -lt 32; $i++) {
        if ($hash[$i] -ne $tail[$i]) { $match = $false; break }
    }
    if (-not $match) {
        throw "OTP ${sourceDesc}: SHA256 integrity check failed (first 0xE0 bytes do not hash to the tail 0x20)."
    }
    $devFlag = [int]$plain[0x19]   # 0 = retail, non-zero = dev (3dbrew OTP_Registers)
    $otpIsDev = ($devFlag -ne 0)
    $modeIsDev = ($mode -eq "dev")
    if ($otpIsDev -ne $modeIsDev) {
        throw "OTP ${sourceDesc}: dev flag byte 0x$($devFlag.ToString('X2')) is inconsistent with -Mode $mode. " +
              "Refusing to derive keys with mismatched keyblob."
    }
    Write-Host "    OTP dev flag: 0x$($devFlag.ToString('X2')) (consistent with -Mode $mode)" -ForegroundColor DarkGray
}

# === Main ===
Write-Host "=== DecryptCTRNand 2.0 ===" -ForegroundColor Cyan
Write-Host "NAND: $NandFile"
Write-Host "boot9: $Boot9File"
Write-Host "OTP: $OtpFile"
Write-Host "Mode: $Mode"

$isDev = ($Mode -eq "dev")
$nandFs = $null
$tmpFiles = @()

try {
    # ---- Input validation ----
    if (-not (Test-Path -LiteralPath $NandFile -PathType Leaf)) { throw "NAND file not found: $NandFile" }
    if (-not (Test-Path -LiteralPath $Boot9File -PathType Leaf)) { throw "boot9 file not found: $Boot9File" }
    if (-not (Test-Path -LiteralPath $OtpFile -PathType Leaf)) { throw "OTP file not found: $OtpFile" }

    $boot9Full = [System.IO.File]::ReadAllBytes($Boot9File)
    if ($boot9Full.Length -ne 0x10000 -and $boot9Full.Length -ne 0x8000) {
        throw "boot9.bin: expected 0x10000 (64KB) or 0x8000 (32KB) bytes, got $($boot9Full.Length)"
    }

    $otpRaw = [System.IO.File]::ReadAllBytes($OtpFile)
    if ($otpRaw.Length -ne 0x100) {
        throw "OTP: expected exactly 0x100 (256) bytes, got $($otpRaw.Length)"
    }

    $nandLen = (Get-Item -LiteralPath $NandFile).Length
    if ($nandLen -lt 0x200) {
        throw "NAND: file too small to contain an NCSD header (< 0x200 bytes)"
    }

    # ---- Step 1: OTP ----
    # OTP key/IV offsets inside boot9. For a 64KB GM9 dump the blobs live at
    # +0x8000 relative to the 32KB base; for a 32KB prot-only dump use base.
    # dev: nk,iv at 0x5700/0x5710 (32KB) or 0xD700/0xD710 (64KB)
    # retail: nk,iv at 0x56E0/0x56F0 (32KB) or 0xD6E0/0xD6F0 (64KB)
    $otpBase = 0x8000
    if ($boot9Full.Length -eq 0x8000) { $otpBase = 0 }
    $nkOff = if ($isDev) { $otpBase + 0x5700 } else { $otpBase + 0x56E0 }
    $ivOff = $nkOff + 0x10
    $otpNk = SubBytes $boot9Full $nkOff 16
    $otpIv = SubBytes $boot9Full $ivOff 16

    if ($OtpDecrypted) {
        Write-Host "`n[*] Using pre-decrypted OTP (validating anyway)"
        $otpPlain = $otpRaw
        Assert-ValidOtpPlain $otpPlain $Mode "from file"
        # Re-encrypt the plaintext back to its raw form: TWL (slot 0x03) derives its
        # dev CustId from the RAW OTP[0:8], so otp_dec.mem alone would give wrong keys.
        $otpRaw = [NandCrypto]::AesCbcEncrypt($otpNk, $otpIv, $otpPlain)
        Write-Host "[+] OTP plaintext valid ($Mode)" -ForegroundColor Green
    } else {
        Write-Host "`n[*] Decrypting OTP..."
        $plain = [NandCrypto]::AesCbcDecrypt($otpNk, $otpIv, $otpRaw)
        Assert-ValidOtpPlain $plain $Mode "decrypted"
        Write-Host "[+] OTP decrypted successfully ($Mode)" -ForegroundColor Green
        $otpPlain = $plain
    }

    # ---- Step 2: CID ----
    if ($CidFile) {
        if (-not (Test-Path -LiteralPath $CidFile -PathType Leaf)) { throw "CID file not found: $CidFile" }
        $cid = [System.IO.File]::ReadAllBytes($CidFile)
        if ($cid.Length -ne 16) {
            throw "CID file: expected exactly 16 bytes, got $($cid.Length)"
        }
        Write-Host "`n[+] CID loaded from file (16 bytes, hidden)"
    } elseif ($CidHex) {
        if ($CidHex -notmatch '^[0-9a-fA-F]{32}$') {
            throw "CID hex: expected exactly 32 hex characters, got '$CidHex'"
        }
        $cid = New-Object byte[] 16
        for ($i = 0; $i -lt 32; $i += 2) {
            $cid[$i/2] = [Convert]::ToByte($CidHex.Substring($i, 2), 16)
        }
        Write-Host "`n[+] CID from hex (hidden)"
    } else {
        Write-Host "`n[!] No CID provided." -ForegroundColor Red
        Write-Host "    NAND AES-CTR nonce = SHA256(CID)[:16], 128-bit, cannot brute-force." -ForegroundColor Red
        Write-Host "    Please provide -CidFile or -CidHex." -ForegroundColor Red
        exit 1
    }

    # ---- Step 3: NCSD parse (with boundary validation) ----
    Write-Host "`n[*] Parsing NCSD header..."
    $nandFs = [System.IO.File]::OpenRead($NandFile)
    $ncsdHeader = New-Object byte[] 0x200
    $headerRead = ReadExactly $nandFs $ncsdHeader 0 0x200
    if ($headerRead -lt 0x200) {
        throw "NAND: truncated NCSD header (read $headerRead of 0x200 bytes)"
    }

    $magic = [System.Text.Encoding]::ASCII.GetString($ncsdHeader, 0x100, 4)
    if ($magic -ne "NCSD") {
        throw "NCSD magic not found at +0x100. Got: '$magic'"
    }
    Write-Host "[+] NCSD magic found at +0x100" -ForegroundColor Green

    # NCSD image size field (media units) - informational
    $ncsdSizeUnits = [BitConverter]::ToUInt32($ncsdHeader, 0x104)
    $ncsdSizeBytes = [uint64]$ncsdSizeUnits * 0x200
    if ($ncsdSizeUnits -ne 0 -and $ncsdSizeBytes -gt [uint64]$nandLen) {
        Write-Host "    [!] NCSD header declares size 0x$($ncsdSizeBytes.ToString('X')) > file length; dump may be truncated" -ForegroundColor Yellow
    }

    $partitions = @()
    $firmCount = 0
    for ($i = 0; $i -lt 8; $i++) {
        $fstype = $ncsdHeader[0x110 + $i]
        $crypttype = $ncsdHeader[0x118 + $i]
        $offsetUnits = [BitConverter]::ToUInt32($ncsdHeader, 0x120 + $i*8)
        $sizeUnits = [BitConverter]::ToUInt32($ncsdHeader, 0x120 + $i*8 + 4)

        if ($fstype -eq 0 -and $crypttype -eq 0) { continue }

        $absOffset = [uint64]$offsetUnits * 0x200
        $absSize = [uint64]$sizeUnits * 0x200

        if ($absOffset -lt 0x200 -and $crypttype -ne 1) {
            Write-Host "    [!] Partition $i : bogus offset 0x$($absOffset.ToString('X')) (overlaps NCSD header), skipped" -ForegroundColor Yellow
            continue
        }
        if ($absSize -eq 0) {
            Write-Host "    [!] Partition $i : zero size, skipped" -ForegroundColor Yellow
            continue
        }
        $absEnd = $absOffset + $absSize
        if ($absEnd -gt [uint64]$nandLen) {
            throw "Partition $i : offset+size 0x$($absEnd.ToString('X')) exceeds NAND file length 0x$($nandLen.ToString('X')). " +
                  "NAND dump is truncated or the partition table is corrupt."
        }

        # --- AES slot mapping (rule-based, refuses unknowns) ---
        # crypt 0x01: fs 0x01 = TWL             -> slot 0x03 (dedicated nonce/key scheme)
        # crypt 0x02: fs 0x01 = Old3DS CTRNAND  -> slot 0x04
        #             fs 0x03 = FIRM            -> slot 0x06
        #             fs 0x04 = AGB_FIRM save   -> slot 0x07
        # crypt 0x03: fs 0x01 = New3DS CTRNAND  -> slot 0x05
        # (pyctr identifies partitions by fs type first, then encryption type;
        #  unknown fs/crypt combinations are refused, not guessed.)
        $slot = 0
        $status = "decrypt"
        if ($crypttype -eq 1) {
            if ($fstype -eq 1) {
                $slot = 0x03
                $status = "twl"   # TWL: dedicated key (raw OTP for dev) + SHA1(CID) nonce + reversed-block CTR
            } else {
                $status = "unknown"
            }
        } elseif ($crypttype -eq 2) {
            if ($fstype -eq 1) { $slot = 0x04 }
            elseif ($fstype -eq 3) { $slot = 0x06 }
            elseif ($fstype -eq 4) { $slot = 0x07 }
            else { $status = "unknown" }
        } elseif ($crypttype -eq 3) {
            if ($fstype -eq 1) { $slot = 0x05 }
            else { $status = "unknown" }
        } else {
            $status = "unknown"
        }

        if ($status -eq "unknown") {
            Write-Host "    [!] Partition $i : unsupported combo fs=0x$($fstype.ToString('X2')) crypt=0x$($crypttype.ToString('X2')) - not decrypting (no guessed slot)" -ForegroundColor Yellow
        }

        $partitions += @{
            Index = $i
            FSType = $fstype
            CryptType = $crypttype
            Offset = [long]$absOffset
            Size = [long]$absSize
            Slot = $slot
            Status = $status
        }

        # FIRM partitions are identified by their occurrence order (FIRM0, FIRM1),
        # mirroring pyctr's firm_count handling. Both still decrypt with slot 0x06.
        $roleTxt = ""
        if ($fstype -eq 3) {
            $roleTxt = if ($firmCount -eq 0) { ", role=FIRM0" } elseif ($firmCount -eq 1) { ", role=FIRM1" } else { ", role=FIRM$firmCount" }
            $firmCount++
        }

        $slotTxt = if ($status -eq "unknown") { "--" } else { "0x$($slot.ToString('X2'))" }
        Write-Host "    Partition $i : slot=$slotTxt offset=0x$($absOffset.ToString('X8')) size=0x$($absSize.ToString('X8')) [$status$roleTxt]"
    }

    # Overlap check between non-empty partition-table entries
    for ($a = 0; $a -lt $partitions.Count; $a++) {
        for ($b = $a + 1; $b -lt $partitions.Count; $b++) {
            $pa = $partitions[$a]
            $pb = $partitions[$b]
            $aStart = [uint64]$pa.Offset
            $aEnd = $aStart + [uint64]$pa.Size
            $bStart = [uint64]$pb.Offset
            $bEnd = $bStart + [uint64]$pb.Size
            if (-not ($aEnd -le $bStart -or $bEnd -le $aStart)) {
                throw "Partition table overlap: partition $($pa.Index) [0x$($aStart.ToString('X'))-0x$($aEnd.ToString('X'))] " +
                      "and partition $($pb.Index) [0x$($bStart.ToString('X'))-0x$($bEnd.ToString('X'))]"
            }
        }
    }

    # --- TWL placement constraints (P0) ---
    # The TWL decrypt coordinate system assumes the partition starts at NAND
    # absolute offset 0 (encrypted ranges [0x1BE:0x200) + [0x12E00:end), with the
    # MBR / blk0x1D / twln FAT checks computed from output offset 0). Reject any
    # NCSD layout that breaks this assumption instead of producing garbage.
    $twlParts = @($partitions | Where-Object { $_.Status -eq "twl" })
    if ($twlParts.Count -gt 1) {
        $twlIdxs = ($twlParts | ForEach-Object { $_.Index }) -join ", "
        throw "NCSD: multiple TWL partitions found (indexes $twlIdxs); expected exactly one."
    }
    if ($twlParts.Count -eq 1) {
        $twl = $twlParts[0]
        if ($twl.Index -ne 0 -or $twl.Offset -ne 0) {
            throw "NCSD: TWL partition must be index 0 with absolute offset 0 " +
                  "(got index $($twl.Index), offset 0x$($twl.Offset.ToString('X'))); refusing to decrypt."
        }
    }

    # ---- Step 4: Keyinit (ported from pyctr, validated on SPR) ----
    Write-Host "`n[*] Keyinit (OTP + boot9 -> console-unique normalKeys)..."
    $b9 = if ($boot9Full.Length -eq 0x10000) { SubBytes $boot9Full 0x8000 0x8000 } else { $boot9Full }

    # keyblob offset in the last-32KB coordinate space: retail=0x5860, dev=0x5C60
    $keyblobOffset = if ($isDev) { 0x5C60 } else { 0x5860 }

    $b9ExtdataKeygen = SubBytes $b9 $keyblobOffset 0x200
    $b9ExtdataOtp = SubBytes $b9ExtdataKeygen 0 0x24

    # console_key_xy = SHA256(OTP_dec[0x90:0xAC] + b9_extdata_otp)
    $otpSeed = SubBytes $otpPlain 0x90 0x1C
    $seedPlusOtp = New-Object byte[] ($otpSeed.Length + $b9ExtdataOtp.Length)
    [Array]::Copy($otpSeed, 0, $seedPlusOtp, 0, $otpSeed.Length)
    [Array]::Copy($b9ExtdataOtp, 0, $seedPlusOtp, $otpSeed.Length, $b9ExtdataOtp.Length)
    $consoleKeyXy = [NandCrypto]::Sha256($seedPlusOtp)

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

    $keyblob = SubBytes $b9 $keyblobOffset 0x400
    $fixedKeyY_CtrnandNew = [byte[]]::new(16)
    $hex = "4D804F4E9990194613A204AC584460BE"
    for ($i = 0; $i -lt 16; $i++) {
        $fixedKeyY_CtrnandNew[$i] = [Convert]::ToByte($hex.Substring($i*2, 2), 16)
    }

    $normalKeys = @{}
    $normalKeys[0x04] = [NandCrypto]::Scramble($slot04_07_KeyX, (SubBytes $keyblob 0x1F0 16))
    $normalKeys[0x05] = [NandCrypto]::Scramble($slot04_07_KeyX, $fixedKeyY_CtrnandNew)
    $normalKeys[0x06] = [NandCrypto]::Scramble($slot04_07_KeyX, (SubBytes $keyblob 0x210 16))
    $normalKeys[0x07] = [NandCrypto]::Scramble($slot04_07_KeyX, (SubBytes $keyblob 0x220 16))

    # TWL slot 0x03: dedicated scheme (dev uses the RAW OTP; $otpRaw is the raw form
    # even in the -OtpDecrypted path thanks to the re-encryption above).
    $twlKey = Get-TwlKey $otpRaw $otpPlain $isDev
    $twlNonce = Get-TwlNonce $cid

    if ($ShowKeys) {
        Write-Host "`n[+] Derived normalKeys:" -ForegroundColor Green
        Write-Host "    slot 0x03 (TWL): $(BytesToHex $twlKey)"
        foreach ($slot in ($normalKeys.Keys | Sort-Object)) {
            Write-Host "    slot 0x$($slot.ToString('X2')): $(BytesToHex $normalKeys[$slot])"
        }
    } else {
        Write-Host "`n[+] Derived normalKeys (slots 0x03-0x07, incl. TWL): OK (hidden; use -ShowKeys to display)" -ForegroundColor Green
    }

    # ---- Step 5: Derive nonce ----
    $nonce = [NandCrypto]::Sha256($cid)[0..15]
    Write-Host "`n[+] CTR nonce derived (SHA256(CID)[:16], hidden)" -ForegroundColor Green
    Write-Host "[+] TWL nonce derived (SHA1(CID)[:16] reversed, hidden)" -ForegroundColor Green

    # ---- Step 6: Decrypt partitions (if OutDir specified) ----
    if ($OutDir) {
        Write-Host "`n[*] Decrypting partitions to: $OutDir" -ForegroundColor Cyan
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

        foreach ($p in $partitions) {
            if ($p.Status -eq "unknown") {
                Write-Host "    Partition $($p.Index): unknown crypt/fs type, skipped" -ForegroundColor Yellow
                continue
            }
            if ($p.Status -eq "twl") {
                Out-TwlPartition $nandFs $p $twlKey $twlNonce $OutDir $Force
                continue
            }
            $slot = $p.Slot
            if (-not $normalKeys.ContainsKey($slot)) {
                Write-Host "    Partition $($p.Index): slot 0x$($slot.ToString('X2')) not derived ($($p.Status)), skipping" -ForegroundColor Yellow
                continue
            }

            $nk = $normalKeys[$slot]
            $outFile = Join-Path $OutDir "partition_$($p.Index)_slot$($slot.ToString('X2')).bin"
            $tmpFile = "$outFile.tmp"

            if (Test-Path -LiteralPath $outFile -PathType Leaf) {
                if (-not $Force) {
                    throw "Output already exists: $outFile . Re-run with -Force to overwrite."
                }
                # -Force: old file is NOT deleted here; replaced atomically at commit
                # time after the new file has been written and validated.
            }
            if (Test-Path -LiteralPath $tmpFile -PathType Leaf) {
                Remove-Item -LiteralPath $tmpFile -Force
            }

            Write-Host "    Partition $($p.Index) (slot 0x$($slot.ToString('X2')))... " -NoNewline

            $outFs = $null
            try {
                $nandFs.Seek($p.Offset, [System.IO.SeekOrigin]::Begin) | Out-Null
                $outFs = [System.IO.File]::Create($tmpFile)
                $tmpFiles += $tmpFile

                $remaining = $p.Size
                $chunkSize = 0x100000
                $buf = New-Object byte[] $chunkSize
                $written = 0L

                while ($remaining -gt 0) {
                    $toRead = [Math]::Min($chunkSize, $remaining)
                    $read = ReadExactly $nandFs $buf 0 $toRead
                    if ($read -lt $toRead) {
                        throw "Partition $($p.Index): NAND truncated - expected $toRead bytes, got $read (partition would be incomplete)"
                    }

                    $absOff = $p.Offset + ($p.Size - $remaining)
                    $blockOffset = [long]($absOff / 16)
                    $counter = [NandCrypto]::AddCounter($nonce, $blockOffset)

                    $decBuf = $buf[0..($read-1)]
                    $decrypted = [NandCrypto]::AesCtrDecrypt($nk, $counter, $decBuf)
                    $outFs.Write($decrypted, 0, $decrypted.Length)
                    $written += $decrypted.Length

                    $remaining -= $read
                }

                if ($written -ne $p.Size) {
                    throw "Partition $($p.Index): wrote $written bytes but expected $($p.Size) (incomplete output)"
                }

                $outFs.Flush()
                $outFs.Dispose()
                $outFs = $null

                # ---- Structural checks (sanity only; AES-CTR is not authenticated) ----
                $checkOk = $true
                $checkNote = ""
                if ($slot -eq 0x04 -or $slot -eq 0x05) {
                    # CTRNAND: first sector must be an MBR with 55AA signature at 0x1FE
                    $head = New-Object byte[] 0x200
                    $hfs = [System.IO.File]::OpenRead($tmpFile)
                    try {
                        $hr = ReadExactly $hfs $head 0 0x200
                        if ($hr -ge 0x200 -and $head[0x1FE] -eq 0x55 -and $head[0x1FF] -eq 0xAA) {
                            $checkNote = "MBR 55AA OK"
                        } else {
                            $checkOk = $false
                            $checkNote = "MBR 55AA MISSING (wrong key/offset?)"
                        }
                    } finally {
                        $hfs.Dispose()
                    }
                } elseif ($slot -eq 0x06) {
                    # FIRM image starts at partition offset 0x00 ("FIRM" magic at +0)
                    $head = New-Object byte[] 0x04
                    $hfs = [System.IO.File]::OpenRead($tmpFile)
                    try {
                        $hr = ReadExactly $hfs $head 0 0x04
                        $firm = [System.Text.Encoding]::ASCII.GetString($head, 0, 4)
                        if ($hr -ge 0x04 -and $firm -eq "FIRM") {
                            $checkNote = "FIRM magic OK"
                        } else {
                            $checkOk = $false
                            $checkNote = "FIRM magic MISSING (wrong key/offset?)"
                        }
                    } finally {
                        $hfs.Dispose()
                    }
                } else {
                    $checkNote = "no structural check defined (slot 0x$($slot.ToString('X2')))"
                }

                if (-not $checkOk) {
                    if (Test-Path -LiteralPath $tmpFile) { Remove-Item -LiteralPath $tmpFile -Force }
                    throw "Partition $($p.Index): structural check failed - $checkNote"
                }

                # SHA-256 record for cross-run comparison
                $shaHex = Get-FileSha256 $tmpFile

                # Commit: atomic replace of the fully-verified .tmp file (old
                # output survives any earlier failure; see Commit-TempFile).
                Commit-TempFile $tmpFile $outFile
                $tmpFiles = $tmpFiles | Where-Object { $_ -ne $tmpFile }

                Write-Host "saved ($([Math]::Round($p.Size / 1MB, 1)) MB, wrote $written bytes, $checkNote)" -ForegroundColor Green
                Write-Host "        SHA-256: $shaHex" -ForegroundColor DarkGray
            } finally {
                if ($outFs) { $outFs.Dispose() }
                if (Test-Path -LiteralPath $tmpFile) { Remove-Item -LiteralPath $tmpFile -Force }
            }
        }
    } else {
        Write-Host "`n[*] No -OutDir specified: keys derived, partitions not written to disk." -ForegroundColor Yellow
    }

    # === Summary ===
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "OTP: valid ($Mode)"
    Write-Host "NCSD: parsed, $($partitions.Count) non-empty partition(s)"
    Write-Host "CID: loaded (hidden)"
    Write-Host "Keyinit: completed (slots 0x03-0x07, incl. TWL)"
    Write-Host "nonce: derived"
    if ($OutDir) {
        Write-Host "Partitions: decrypted to $OutDir (structural checks applied)"
        Write-Host "Note: AES-CTR provides no integrity authentication; checks are structural sanity checks only." -ForegroundColor DarkGray
    } else {
        Write-Host "Partitions: not decrypted (no -OutDir)"
    }
    Write-Host "`nDone." -ForegroundColor Cyan
}
catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`nDecryption aborted; no incomplete partition files were left behind." -ForegroundColor Yellow
    exit 1
}
finally {
    if ($nandFs) { $nandFs.Dispose() }
}
