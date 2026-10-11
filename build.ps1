<#
.SYNOPSIS
  Builds, tests and packages NetHunter Monitor as a portable, self-contained Windows x64 release.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\build.ps1             # test + publish + zip
  powershell -ExecutionPolicy Bypass -File .\build.ps1 -SkipTests  # publish + zip only
#>
param(
    [switch]$SkipTests,
    [string]$Version = "1.0.0"
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw "The .NET 8 SDK is required to build (not to run). https://dotnet.microsoft.com/download/dotnet/8.0" }

if (-not $SkipTests) {
    Write-Host "== Running tests" -ForegroundColor Cyan
    dotnet test NetHunterMonitor.sln -c Release
    if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
}

$out = Join-Path $PSScriptRoot "dist\NetHunterMonitor"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
$common = @('-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
    '-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true', '-p:EnableCompressionInSingleFile=true',
    '-p:DebugType=none', '-p:DebugSymbols=false', "-p:Version=$Version", '-o', $out)

Write-Host "== Publishing desktop app" -ForegroundColor Cyan
dotnet publish src\NetHunter.App @common
if ($LASTEXITCODE -ne 0) { throw "Publish failed (app)" }
Write-Host "== Publishing CLI" -ForegroundColor Cyan
dotnet publish src\NetHunter.Cli @common
if ($LASTEXITCODE -ne 0) { throw "Publish failed (cli)" }

# Ship docs and an example IOC list; runtime folders (config/database/logs) are created on first run.
Copy-Item README.md, LICENSE $out
New-Item -ItemType Directory -Force (Join-Path $out "docs") | Out-Null
Copy-Item docs\*.md (Join-Path $out "docs")
New-Item -ItemType Directory -Force (Join-Path $out "samples") | Out-Null
Copy-Item samples\* (Join-Path $out "samples")

$zip = Join-Path $PSScriptRoot "dist\NetHunterMonitor-$Version-win-x64-portable.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path $out -DestinationPath $zip
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $(Split-Path $zip -Leaf)" | Set-Content -Encoding ascii "$zip.sha256"
Write-Host "== Done: $zip" -ForegroundColor Green
Write-Host "   SHA-256 $hash"
