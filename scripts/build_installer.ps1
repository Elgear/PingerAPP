param(
    [string]$InnoSetupCompiler = "",
    [switch]$BuildApp
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if ($BuildApp) {
    & (Join-Path $repoRoot "scripts\build_windows.ps1") -Clean
}

$appExe = Join-Path $repoRoot "dist\PingerApp\PingerApp.exe"
if (-not (Test-Path -LiteralPath $appExe)) {
    throw "PyInstaller output was not found: $appExe. Run .\scripts\build_windows.ps1 -Clean first, or pass -BuildApp."
}

$candidates = @()
if ($InnoSetupCompiler) {
    $candidates += $InnoSetupCompiler
}

$pathCommand = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
if ($pathCommand) {
    $candidates += $pathCommand.Source
}

$candidates += @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
)

$compiler = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $compiler) {
    throw "Inno Setup compiler ISCC.exe was not found. Install Inno Setup 6, add ISCC.exe to PATH, or pass -InnoSetupCompiler."
}

$scriptPath = Join-Path $repoRoot "installer\PingerApp.iss"
& $compiler $scriptPath
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup failed with exit code $LASTEXITCODE."
}

$installerPath = Join-Path $repoRoot "installer_output\PingerAppSetup-0.1.0.exe"
if (Test-Path -LiteralPath $installerPath) {
    Write-Host "Built $installerPath"
} else {
    Write-Host "Installer build completed. Check installer_output for the generated setup executable."
}
