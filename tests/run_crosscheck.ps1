# run_crosscheck.ps1 - cross-validates the three DecryptCTRNand implementations
# against the synthetic test vectors (tests/vectors) and the oracle
# (tests/expected), plus negative tests (overwrite protection, wrong mode,
# truncated NAND, -OtpDecrypted path).
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
    "partition_0_slot04.bin",
    "partition_1_slot06.bin",
    "partition_2_slot07.bin",
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
    switch ($impl) {
        "ps1" {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "DecryptCTRNand.ps1") `
                -NandFile $nand -Boot9File $boot9 -OtpFile $otp -CidFile $cid -Mode $mode -OutDir $outDir -Force
        }
        "py" {
            & python (Join-Path $root "DecryptCTRNand.py") --nand $nand --boot9 $boot9 --otp $otp --cid-file $cid --mode $mode --outdir $outDir --force
        }
        "java" {
            & java -jar $JavaJar --cli --nand $nand --boot9 $boot9 --otp $otp --cid-file $cid --mode $mode --outdir $outDir --force
        }
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$impl/$mode$extraArgs failed with exit code $LASTEXITCODE"
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

# ---- 4. -OtpDecrypted path ----
Write-Host "`n=== -OtpDecrypted path (py / dev) ==="
$nandD = Join-Path $vec "nand_dev.bin"
$boot9V = Join-Path $vec "boot9.bin"
$cidV = Join-Path $vec "cid.bin"
$otpPlainD = Join-Path $vec "otp_plain_dev.bin"
$outOtp = Join-Path $outRoot "py_dec_dev"
if (Test-Path -LiteralPath $outOtp) { Remove-Item -Recurse -Force -LiteralPath $outOtp }
New-Item -ItemType Directory -Force -Path $outOtp | Out-Null
& python (Join-Path $root "DecryptCTRNand.py") --nand $nandD --boot9 $boot9V --otp $otpPlainD --otp-dec --cid-file $cidV --mode dev --outdir $outOtp --force
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
& python (Join-Path $root "DecryptCTRNand.py") --nand $nandD --boot9 $boot9V --otp (Join-Path $vec "otp_dev.bin") --cid-file $cidV --mode retail --outdir $outNeg1 2> $negLog | Out-Null
if ($LASTEXITCODE -eq 0) { $negFail++; Write-Host "[FAIL] dev-flag consistency: retail mode + dev OTP should have failed" -ForegroundColor Red }
else { Write-Host "[PASS] dev-flag consistency (retail mode rejects dev OTP)" -ForegroundColor Green }

# 5.3 truncated NAND must fail
$truncNand = Join-Path $vec "nand_truncated.bin"
$fullBytes = [System.IO.File]::ReadAllBytes($nandD)
$half = [Math]::Max(0x400, [int]($fullBytes.Length / 2))
[System.IO.File]::WriteAllBytes($truncNand, $fullBytes[0..($half - 1)])
& python (Join-Path $root "DecryptCTRNand.py") --nand $truncNand --boot9 $boot9V --otp (Join-Path $vec "otp_dev.bin") --cid-file $cidV --mode dev --outdir $outNeg1 2> $negLog | Out-Null
if ($LASTEXITCODE -eq 0) { $negFail++; Write-Host "[FAIL] truncated NAND should have failed" -ForegroundColor Red }
else { Write-Host "[PASS] truncated NAND rejected" -ForegroundColor Green }

# 5.4 bad CID hex must fail
& python (Join-Path $root "DecryptCTRNand.py") --nand $nandD --boot9 $boot9V --otp (Join-Path $vec "otp_dev.bin") --cid "1234" --mode dev --outdir $outNeg1 2> $negLog | Out-Null
if ($LASTEXITCODE -eq 0) { $negFail++; Write-Host "[FAIL] bad CID hex should have failed" -ForegroundColor Red }
else { Write-Host "[PASS] bad CID hex rejected" -ForegroundColor Green }

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
