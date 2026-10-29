# Patient Portal Fast Track 7 — offline tests only; NO ADMIN, NO DEPLOYMENT.
param(
    [string]$PythonExe = '',
    [switch]$IncludeSynthetic
)
$ErrorActionPreference = 'Stop'
try {
    $principal = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'HOLD: Use ordinary PowerShell, not Administrator.'
    }
    if ($PSScriptRoot.StartsWith('C:\PatientPortal\staging\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'HOLD: Do not run Fast Track tests from writable staging.'
    }
    if (-not $PythonExe) {
        $candidates = @(
            (Join-Path (Split-Path -Parent $PSScriptRoot) 'PatientPortal-FastTrack-v7-venv\Scripts\python.exe'),
            'C:\PatientPortal\staging\stage6-6-acceptance\.venv-stage66\Scripts\python.exe'
        )
        foreach ($candidate in $candidates) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $PythonExe = $candidate
                break
            }
        }
        if (-not $PythonExe) {
            $command = Get-Command python.exe -ErrorAction SilentlyContinue
            if ($command) { $PythonExe = $command.Source }
        }
    }
    if (-not $PythonExe -or -not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
        throw 'HOLD: Python not found. See CODEX_START_HERE_BG.md for an isolated venv.'
    }
    $runner = Join-Path $PSScriptRoot 'tools\fasttrack_runner.py'
    if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
        throw 'HOLD: Safe test runner missing.'
    }
    if ($IncludeSynthetic) {
        & $PythonExe -B $runner --include-synthetic
    } else {
        & $PythonExe -B $runner
    }
    if ($LASTEXITCODE -ne 0) {
        throw 'HOLD: One or more offline checks failed; see reports.'
    }
} catch {
    Write-Host ('FAIL/HOLD: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host 'RELEASE GATE: HOLD / NO-GO.' -ForegroundColor Yellow
    exit 1
}
