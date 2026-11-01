# run_crosscheck.ps1 - cross-validates the three DecryptCTRNand implementations
# against the synthetic test vectors (tests/vectors) and the oracle
# (tests/expected), plus negative tests (overwrite protection, wrong mode,
# truncated NAND, -OtpDecrypted path, publish/commit safety, TWL layout rules).
#
# Usage:
#   .\run_crosscheck.ps1                     # PS1 + Python only
#   .\run_crosscheck.ps1 -JavaJar ..\java\DecryptCTRNandGUI.jar
#
# Exit code 0 = all checks passed.

param(
    [string]$JavaJar = ""
)

$ErrorActionPreference = "Stop"
$tests = $PSScriptRoot
$root = Split-Path -Parent $PSScriptRoot
$vec = Join-Path $tests "vectors"
$exp = Join-Path $tests "expected"
$outRoot = Join-Path $tests "out"

$EXPECTED = @(
    "partition_0_slot03.bin",   # TWL (now truly encrypted in the vectors)
    "partition_1_slot04.bin",
    "partition_2_slot06.bin",
    "partition_3_slot07.bin",
    "partition_4_slot05.bin"
)

$failures = @()

function Compare-Files([string]$a, [string]$b) {
    $ba = [System.IO.File]::ReadAllBytes($a)
    $bb = [System.IO.File]::ReadAllBytes($b)
    if ($ba.Length -ne $bb.Length) { return $false }
    for ($i = 0; $i -lt $ba.Length; $i++) {
        if ($ba[$i] -ne $bb[$i]) { return $false }
    }
    return $true
}

# name -> SHA-256 of every file in a directory (used to prove that a failed
# run did not touch the outputs of the previous successful run).
function Get-DirFingerprint([string]$dir) {
    $map = @{}
    if (-not (Test-Path -LiteralPath $dir)) { return $map }
    foreach ($f in Get-ChildItem -LiteralPath $dir -File) {
        $map[$f.Name] = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
    }
    return $map
}

# Any leftover .tmp means -Force / commit cleanup regressed.
function Get-TempLeftovers([string]$dir) {
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    return @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -like '*.tmp' })
}

# Copy a NAND vector and patch the NCSD header (scriptblock receives byte[]).
function New-MutatedNand([string]$src, [string]$dst, [scriptblock]$patch) {
    $bytes = [System.IO.File]::ReadAllBytes($src)
    & $patch $bytes
    [System.IO.File]::WriteAllBytes($dst, $bytes)
}

# Runs one implementation; stdout flows through to the caller.
# $outDir is decided by the caller so the function never returns a value.
function Invoke-Impl([string]$impl, [string]$mode, [string]$outDir, [string]$extraArgs) {
    $nand = Join-Path $vec "nand_$mode.bin"
    $otp = Join-Path $vec "otp_$mode.bin"
    $boot9 = Join-Path $vec "boot9.bin"
    $cid = Join-Path $vec "cid.bin"

    if (Test-Path -LiteralPath $outDir) { Remove-Item -Recurse -Force -LiteralPath $outDir }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    Write-Host "--- $impl / $mode $extraArgs ---"
    # All three implementations use the PS1-identical parameter names
    # (case-insensitive). The Java jar is invoked WITHOUT the --cli prefix to
    # prove the CLI entry works directly from the double-clickable jar.
    switch ($impl) {
        "ps1" {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "DecryptCTRNand.ps1") `
                -NandFile $nand -Boot9File $boot9 -OtpFile $otp -CidFile $cid -Mode $mode -OutDir $outDir -Force
        }
        "py" {
            & python (Join-Path $root "DecryptCTRNand.py") -NandFile $nand -Boot9File $boot9 -OtpFile $otp -CidFile $cid -Mode $mode -OutDir $outDir -Force
        }
        "java" {
            & java -jar $JavaJar -NandFile $nand -Boot9File $boot9 -OtpFile $otp -CidFile $cid -Mode $mode -OutDir $outDir -Force
        }
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$impl/$mode$extraArgs failed with exit code $LASTEXITCODE"
    }
}

# Runs one implementation with the given arguments and returns its combined
# stdout+stderr; $LASTEXITCODE of the caller reflects the native exit code.
function Invoke-Neg([string]$impl, [string[]]$negArgs) {
    switch ($impl) {
        "ps1" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "DecryptCTRNand.ps1") @negArgs 2>&1 | Out-String | Write-Output }
        "py" { & python (Join-Path $root "DecryptCTRNand.py") @negArgs 2>&1 | Out-String | Write-Output }
        "java" { & java -jar $JavaJar @negArgs 2>&1 | Out-String | Write-Output }
    }
}

# ---- 1. generate vectors ----
Write-Host "=== Generating synthetic test vectors ==="
& python (Join-Path $tests "make_testvectors.py")
if ($LASTEXITCODE -ne 0) { throw "make_testvectors.py failed" }

# ---- 2. positive runs ----
$impls = @("ps1", "py")
if ($JavaJar -ne "") { $impls += "java" }

$outputs = @{}
foreach ($mode in @("dev", "retail")) {
    foreach ($impl in $impls) {
        $outDir = Join-Path $outRoot "${impl}_$mode"
        $outputs["$impl/$mode"] = $outDir
        Invoke-Impl $impl $mode $outDir ""
    }
}

# ---- 3. compare against expected + each other ----
Write-Host "`n=== Comparing decrypted outputs ==="
foreach ($mode in @("dev", "retail")) {
    foreach ($impl in $impls) {
        $dir = $outputs["$impl/$mode"]
        foreach ($name in $EXPECTED) {
            $got = Join-Path $dir $name
            $want = Join-Path $exp $name
            if (-not (Test-Path -LiteralPath $got)) {
                $failures += "$impl/$mode missing output $name"
                Write-Host "[FAIL] $impl/$mode missing $name" -ForegroundColor Red
                continue
            }
            if (Compare-Files $got $want) {
                Write-Host "[PASS] $impl/$mode $name matches oracle" -ForegroundColor Green
            } else {
                $failures += "$impl/$mode $name differs from oracle"
                Write-Host "[FAIL] $impl/$mode $name differs from oracle" -ForegroundColor Red
            }
        }
    }
    # impl vs impl (byte equality across implementations)
    if ($impls.Count -ge 2) {
        $da = $outputs["$($impls[0])/$mode"]
        $db = $outputs["$($impls[1])/$mode"]
        foreach ($name in $EXPECTED) {
            $fa = Join-Path $da $name
            $fb = Join-Path $db $name
            if ((Test-Path -LiteralPath $fa) -and (Test-Path -LiteralPath $fb) -and (Compare-Files $fa $fb)) {
                Write-Host "[PASS] $($impls[0]) == $($impls[1]) / $mode / $name" -ForegroundColor Green
            } else {
                $failures += "$($impls[0]) != $($impls[1]) / $mode / $name"
                Write-Host "[FAIL] $($impls[0]) != $($impls[1]) / $mode / $name" -ForegroundColor Red
            }
        }
    }
}

# ---- 3b. TWL boundary slices (audit-recommended targeted ranges) ----
# The full-partition oracle comparison above already covers these byte ranges,
# but check them explicitly so a regression in a specific boundary is named
# instead of hiding inside a whole-partition mismatch.
Write-Host "`n=== TWL boundary slices (against oracle) ==="
$TWL_SLICES = @(
    @{ Name = "MBR misaligned head 0x1BE-0x1FF";   Off = 0x1BE; Len = 0x41 },
    @{ Name = "cross counter block 0x1F0-0x20F";   Off = 0x1F0; Len = 0x20 },
    @{ Name = "MBR enc end boundary 0x1F8-0x207";  Off = 0x1F8; Len = 0x10 },
    @{ Name = "FAT start 0x12E00-0x12E1F";         Off = 0x12E00; Len = 0x20 },
    @{ Name = "FAT single block 0x12E00-0x12E0F";  Off = 0x12E00; Len = 0x10 }
)
foreach ($mode in @("dev", "retail")) {
    foreach ($impl in $impls) {
        $dir = $outputs["$impl/$mode"]
        $twlGot = Join-Path $dir "partition_0_slot03.bin"
        $twlWant = Join-Path $exp "partition_0_slot03.bin"
        if (-not (Test-Path -LiteralPath $twlGot)) { continue }
        foreach ($sl in $TWL_SLICES) {
            $g = [System.IO.File]::ReadAllBytes($twlGot)
            $w = [System.IO.File]::ReadAllBytes($twlWant)
            $off = [int]$sl.Off; $len = [int]$sl.Len
            $ok = $true
            if ($g.Length -lt $off + $len -or $w.Length -lt $off + $len) { $ok = $false }
            else {
                for ($i = 0; $i -lt $len; $i++) {
                    if ($g[$off + $i] -ne $w[$off + $i]) { $ok = $false; break }
                }
            }
            if ($ok) {
                Write-Host "[PASS] $impl/$mode $($sl.Name)" -ForegroundColor Green
            } else {
                $failures += "$impl/$mode TWL slice differs from oracle: $($sl.Name)"
                Write-Host "[FAIL] $impl/$mode $($sl.Name)" -ForegroundColor Red
            }
        }
    }
}

# ---- 3c. -Force over existing outputs (replace path) ----
# The positive runs always start from a fresh directory, so they never exercise
# the "target already exists" branch. Re-run in place with -Force and require
# identical bytes: this drives File::Replace / os.replace / ATOMIC_MOVE over an
# output file that already exists.
Write-Host "`n=== -Force over existing outputs (replace path) ==="
foreach ($mode in @("dev", "retail")) {
    foreach ($impl in $impls) {
        $dir = $outputs["$impl/$mode"]
        $before = Get-DirFingerprint $dir
        $null = Invoke-Neg $impl @("-NandFile", (Join-Path $vec "nand_$mode.bin"),
            "-Boot9File", (Join-Path $vec "boot9.bin"), "-OtpFile", (Join-Path $vec "otp_$mode.bin"),
            "-CidFile", (Join-Path $vec "cid.bin"), "-Mode", $mode, "-OutDir", $dir, "-Force")
        $ok = ($LASTEXITCODE -eq 0)
        if ($ok) {
            $after = Get-DirFingerprint $dir
            if ($after.Count -ne $before.Count) { $ok = $false }
            else {
                foreach ($k in $before.Keys) {
                    if (-not $after.ContainsKey($k) -or $after[$k] -ne $before[$k]) { $ok = $false; break }
                }
            }
        }
        $tmpLeft = @(Get-TempLeftovers $dir)
        if ($ok -and $tmpLeft.Count -eq 0) {
            Write-Host "[PASS] $impl/$mode -Force replaced existing outputs in place" -ForegroundColor Green
        } else {
            $failures += "$impl/$mode -Force overwrite of existing outputs failed"
            Write-Host "[FAIL] $impl/$mode -Force overwrite of existing outputs" -ForegroundColor Red
        }
    }
}

# ---- 4. -OtpDecrypted path ----
Write-Host "`n=== -OtpDecrypted path (py / dev) ==="
$nandD = Join-Path $vec "nand_dev.bin"
$boot9V = Join-Path $vec "boot9.bin"
$cidV = Join-Path $vec "cid.bin"
$otpPlainD = Join-Path $vec "otp_plain_dev.bin"
$outOtp = Join-Path $outRoot "py_dec_dev"
if (Test-Path -LiteralPath $outOtp) { Remove-Item -Recurse -Force -LiteralPath $outOtp }
New-Item -ItemType Directory -Force -Path $outOtp | Out-Null
& python (Join-Path $root "DecryptCTRNand.py") -NandFile $nandD -Boot9File $boot9V -OtpFile $otpPlainD -OtpDecrypted -CidFile $cidV -Mode dev -OutDir $outOtp -Force
if ($LASTEXITCODE -ne 0) { $failures += "py/otp-dec dev failed"; Write-Host "[FAIL] otp-dec run failed" -ForegroundColor Red }
else {
    $ok = $true
    foreach ($name in $EXPECTED) {
        if (-not (Compare-Files (Join-Path $outOtp $name) (Join-Path $exp $name))) { $ok = $false }
    }
    if ($ok) { Write-Host "[PASS] -OtpDecrypted dev output matches oracle" -ForegroundColor Green }
    else { $failures += "-OtpDecrypted dev mismatch"; Write-Host "[FAIL] -OtpDecrypted dev mismatch" -ForegroundColor Red }
}

# ---- 5. negative tests ----
# Note: these runs are EXPECTED to fail; the stderr they produce must not
# become terminating errors (PS 5.1 turns native stderr into error records
# under $ErrorActionPreference=Stop when merged with 2>&1).
Write-Host "`n=== Negative tests ==="
$negFail = 0
$savedEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$negLog = Join-Path $outRoot "neg_err.log"

# 5.1 overwrite protection (PS1 without -Force must fail)
$outNeg1 = Join-Path $outRoot "neg_overwrite"
if (Test-Path -LiteralPath $outNeg1) { Remove-Item -Recurse -Force -LiteralPath $outNeg1 }
New-Item -ItemType Directory -Force -Path $outNeg1 | Out-Null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "DecryptCTRNand.ps1") `
    -NandFile $nandD -Boot9File $boot9V -OtpFile (Join-Path $vec "otp_dev.bin") -CidFile $cidV -Mode dev -OutDir $outNeg1 -Force 2> $negLog | Out-Null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "DecryptCTRNand.ps1") `
    -NandFile $nandD -Boot9File $boot9V -OtpFile (Join-Path $vec "otp_dev.bin") -CidFile $cidV -Mode dev -OutDir $outNeg1 2> $negLog | Out-Null
if ($LASTEXITCODE -eq 0) { $negFail++; Write-Host "[FAIL] overwrite protection: 2nd run without -Force should have failed" -ForegroundColor Red }
else { Write-Host "[PASS] overwrite protection (no -Force refuses to overwrite)" -ForegroundColor Green }

# 5.2 wrong mode: retail mode with dev OTP must fail (dev flag consistency)
& python (Join-Path $root "DecryptCTRNand.py") -NandFile $nandD -Boot9File $boot9V -OtpFile (Join-Path $vec "otp_dev.bin") -CidFile $cidV -Mode retail -OutDir $outNeg1 2> $negLog | Out-Null
if ($LASTEXITCODE -eq 0) { $negFail++; Write-Host "[FAIL] dev-flag consistency: retail mode + dev OTP should have failed" -ForegroundColor Red }
else { Write-Host "[PASS] dev-flag consistency (retail mode rejects dev OTP)" -ForegroundColor Green }

# 5.3 truncated NAND must fail
$truncNand = Join-Path $vec "nand_truncated.bin"
$fullBytes = [System.IO.File]::ReadAllBytes($nandD)
$half = [Math]::Max(0x400, [int]($fullBytes.Length / 2))
[System.IO.File]::WriteAllBytes($truncNand, $fullBytes[0..($half - 1)])
& python (Join-Path $root "DecryptCTRNand.py") -NandFile $truncNand -Boot9File $boot9V -OtpFile (Join-Path $vec "otp_dev.bin") -CidFile $cidV -Mode dev -OutDir $outNeg1 2> $negLog | Out-Null
if ($LASTEXITCODE -eq 0) { $negFail++; Write-Host "[FAIL] truncated NAND should have failed" -ForegroundColor Red }
else { Write-Host "[PASS] truncated NAND rejected" -ForegroundColor Green }

# 5.4 bad CID hex must fail
& python (Join-Path $root "DecryptCTRNand.py") -NandFile $nandD -Boot9File $boot9V -OtpFile (Join-Path $vec "otp_dev.bin") -CidHex "1234" -Mode dev -OutDir $outNeg1 2> $negLog | Out-Null
if ($LASTEXITCODE -eq 0) { $negFail++; Write-Host "[FAIL] bad CID hex should have failed" -ForegroundColor Red }
else { Write-Host "[PASS] bad CID hex rejected" -ForegroundColor Green }

# 5.5 commit safety: a failing -Force run must leave the previous outputs
# byte-identical and must not leave any .tmp file behind (P0 semantics).
# A wrong CID makes every partition fail its structural check *after* the
# decrypted data was written to .tmp, which is the interesting path.
Write-Host "`n=== Publish safety: failure keeps old outputs, no .tmp left ==="
$presDir = Join-Path $outRoot "neg_preserve"
$badCid = "0123456789ABCDEF0123456789ABCDEF"
foreach ($impl in $impls) {
    $dir = Join-Path $presDir $impl
    if (Test-Path -LiteralPath $dir) { Remove-Item -Recurse -Force $dir }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $common = @("-NandFile", $nandD, "-Boot9File", $boot9V, "-OtpFile", (Join-Path $vec "otp_dev.bin"),
                "-Mode", "dev", "-OutDir", $dir, "-Force")
    $null = Invoke-Neg $impl ($common + @("-CidFile", $cidV))
    if ($LASTEXITCODE -ne 0) {
        $negFail++; Write-Host "[FAIL] $impl warm-up run failed" -ForegroundColor Red; continue
    }
    $before = Get-DirFingerprint $dir
    $null = Invoke-Neg $impl ($common + @("-CidHex", $badCid))
    if ($LASTEXITCODE -eq 0) {
        $negFail++; Write-Host "[FAIL] $impl wrong-CID run should have failed" -ForegroundColor Red; continue
    }
    $after = Get-DirFingerprint $dir
    $same = ($before.Count -eq $after.Count)
    if ($same) {
        foreach ($k in $before.Keys) {
            if (-not $after.ContainsKey($k) -or $after[$k] -ne $before[$k]) { $same = $false; break }
        }
    }
    $tmpLeft = @(Get-TempLeftovers $dir)
    if ($same -and $tmpLeft.Count -eq 0) {
        Write-Host "[PASS] $impl failure kept old outputs intact, no .tmp left" -ForegroundColor Green
    } else {
        $negFail++
        Write-Host "[FAIL] $impl failure changed old outputs or left $($tmpLeft.Count) .tmp file(s)" -ForegroundColor Red
    }
}

# 5.6/5.7 TWL layout rules: TWL must be unique, index 0 and at absolute offset 0.
Write-Host "`n=== TWL layout rules (must be rejected) ==="
$multiTwlNand = Join-Path $outRoot "nand_multi_twl.bin"
$twlOffsetNand = Join-Path $outRoot "nand_twl_offset.bin"

# an extra fs=1/crypt=1 entry (index 5) in the free gap 0x18000..0x19000
New-MutatedNand $nandD $multiTwlNand {
    param($b)
    $b[0x115] = 1; $b[0x11D] = 1
    [BitConverter]::GetBytes([uint32](0x18000 / 0x200)).CopyTo($b, 0x148)
    [BitConverter]::GetBytes([uint32](0x1000 / 0x200)).CopyTo($b, 0x14C)
}
# TWL (entry 0) moved to absolute offset 0x200
New-MutatedNand $nandD $twlOffsetNand {
    param($b)
    [BitConverter]::GetBytes([uint32](0x200 / 0x200)).CopyTo($b, 0x120)
}

$twlCases = @(
    @{ Name = "duplicate TWL partition"; Nand = $multiTwlNand; Expect = "multiple TWL partitions" },
    @{ Name = "TWL at non-zero offset"; Nand = $twlOffsetNand; Expect = "absolute offset 0" }
)
foreach ($impl in $impls) {
    foreach ($c in $twlCases) {
        $twlArgs = @("-NandFile", $c.Nand, "-Boot9File", $boot9V, "-OtpFile", (Join-Path $vec "otp_dev.bin"),
                     "-CidFile", $cidV, "-Mode", "dev")
        $outTxt = Invoke-Neg $impl $twlArgs
        if ($LASTEXITCODE -ne 0 -and $outTxt -match [regex]::Escape($c.Expect)) {
            Write-Host "[PASS] $impl rejected $($c.Name)" -ForegroundColor Green
        } else {
            $negFail++
            Write-Host "[FAIL] $impl did not reject $($c.Name) with '$($c.Expect)' (exit $LASTEXITCODE)" -ForegroundColor Red
        }
    }
}

$ErrorActionPreference = $savedEAP

# ---- summary ----
Write-Host "`n=== Summary ==="
if ($failures.Count -eq 0 -and $negFail -eq 0) {
    Write-Host "ALL CROSS-CHECKS PASSED" -ForegroundColor Green
    exit 0
} else {
    foreach ($f in $failures) { Write-Host "[FAIL] $f" -ForegroundColor Red }
    Write-Host "$($failures.Count) comparison failures, $negFail negative-test failures" -ForegroundColor Red
    exit 1
}
