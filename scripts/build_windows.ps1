param(
    [string]$Python = ".\.packaging-venv\Scripts\python.exe",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Python interpreter not found: $Python"
}

if ($Clean) {
    Remove-Item -LiteralPath ".\build", ".\dist" -Recurse -Force -ErrorAction SilentlyContinue
}

& $Python -m PyInstaller --noconfirm ".\PingerApp.spec"

$exe = Join-Path $repoRoot "dist\PingerApp\PingerApp.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "Build finished but executable was not found: $exe"
}

Write-Host "Built $exe"
