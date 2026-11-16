# Дымовой прогон: все лимиты и журнал на живой машине.
# Запуск: powershell -ExecutionPolicy Bypass -File scripts\smoke.ps1
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONUTF8 = "1"

$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $python = (Get-Command python).Source
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("agent-sandbox-smoke-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
Push-Location $work

# Отдельная политика: разрешаем имя, которого нет, чтобы увидеть код 127, а не 126.
$missingPolicy = Join-Path $work "allow-missing.toml"
@"
[policy]
allow_programs = ["no-such-program-xyz"]
"@ | Set-Content -Path $missingPolicy -Encoding UTF8

$failed = 0
function Check($name, $expectedState, $expectedExit, $arguments) {
    $raw = & $python -m agentsandbox @arguments
    $code = $LASTEXITCODE
    try {
        $result = $raw | ConvertFrom-Json
    } catch {
        Write-Host ("[провал] {0}: не разобрал JSON`n{1}" -f $name, $raw)
        $script:failed++
        return
    }
    if ($result.state -ne $expectedState -or $code -ne $expectedExit) {
        Write-Host ("[провал] {0}: состояние {1} (ждали {2}), код {3} (ждали {4})" -f `
            $name, $result.state, $expectedState, $code, $expectedExit)
        $script:failed++
        return
    }
    Write-Host ("[ок]     {0}: {1}, exit {2}, {3:N2} с, {4:N0} МБ" -f `
        $name, $result.state, $code, $result.duration, $result.peak_memory_mb)
}

try {
    Write-Host "== doctor =="
    & $python -m agentsandbox doctor
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[провал] doctor"
        $failed++
    }

    Write-Host "`n== лимиты =="
    Check "успех" "succeeded" 0 @(
        "run", "--no-echo", "--json", "--", $python, "-c", "print('ok')")
    Check "код возврата" "failed" 3 @(
        "run", "--no-echo", "--json", "--", $python, "-c", "raise SystemExit(3)")
    Check "стенное время" "timeout" 124 @(
        "run", "--no-echo", "--json", "--timeout", "1", "--",
        $python, "-c", "import time; time.sleep(60)")
    Check "процессор" "cpu-limit" 152 @(
        "run", "--no-echo", "--json", "--cpu", "1", "--timeout", "60", "--",
        $python, "-c", "x = 0`nwhile True: x += 1")
    Check "память" "memory-limit" 137 @(
        "run", "--no-echo", "--json", "--memory", "64", "--",
        $python, "-c", "bytearray(400 * 1024 * 1024)")
    Check "политика" "denied" 126 @(
        "run", "--no-echo", "--json", "--", "curl", "--version")
    Check "программа не найдена" "error" 127 @(
        "run", "--no-echo", "--json", "--policy", $missingPolicy, "--", "no-such-program-xyz")

    Write-Host "`n== журнал =="
    & $python -m agentsandbox audit verify
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[провал] audit verify"
        $failed++
    }
    & $python -m agentsandbox audit tail --limit 3
}
finally {
    Pop-Location
    Remove-Item -Recurse -Force $work
}

if ($failed -gt 0) {
    Write-Host "`nпровалов: $failed" -ForegroundColor Red
    exit 1
}
Write-Host "`nвсё чисто" -ForegroundColor Green
exit 0
