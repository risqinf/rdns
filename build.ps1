# build.ps1 — build all rdns binaries on Windows (or any OS with Go).
#
#   .\build.ps1                      # default: linux/amd64 + linux/arm64 + windows certs
#   .\build.ps1 -Arch amd64          # only amd64 (faster)
#   .\build.ps1 -Version v0.2.0      # stamp a version
#
# Output goes to .\dist\ with a SHA256SUMS.txt. See SETUP.md §B for which
# file goes to which server.

param(
    [string[]]$Arch = @('amd64', 'arm64'),
    [string]$Version = 'v0.2.0',
    [switch]$SkipWindowsCerts
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Set-Location $root

$dist = Join-Path $root 'dist'
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Force -Path $dist | Out-Null

# (binary name, package path, target OS list)
$targets = @(
    @{ Name = 'rdns-client'; Pkg = './cmd/rdns-client';  OS = @('linux') }
    @{ Name = 'rdns-server'; Pkg = './cmd/rdns-server';  OS = @('linux') }
    @{ Name = 'rdns-certs';  Pkg = './tools/rdns-certs'; OS = @('linux') }
)

$ldflags = "-s -w -X main.version=$Version"
$fail = 0

function Build-Target {
    param($name, $pkg, $os, $arch)
    $ext = if ($os -eq 'windows') { '.exe' } else { '' }
    $out = Join-Path $dist "$name-$os-$arch$ext"
    $env:CGO_ENABLED = '0'
    $env:GOOS = $os
    $env:GOARCH = $arch
    try {
        & go build -trimpath -ldflags $ldflags -o $out $pkg
        if ($LASTEXITCODE -ne 0) { throw "go build exited $LASTEXITCODE" }
        $mb = [math]::Round((Get-Item $out).Length / 1MB, 2)
        Write-Host ("  OK   {0,-28} {1,6} MB" -f "$name-$os-$arch$ext", $mb) -ForegroundColor Green
    } catch {
        Write-Host ("  FAIL {0}: {1}" -f $name, $_) -ForegroundColor Red
        $script:fail++
    }
}

Write-Host "`nbuilding rdns $Version" -ForegroundColor Cyan
foreach ($t in $targets) {
    foreach ($os in $t.OS) {
        foreach ($a in $Arch) {
            Build-Target $t.Name $t.Pkg $os $a
        }
    }
}
# rdns-certs for Windows: the operator mints the PKI from a PC (SETUP.md C.1).
if (-not $SkipWindowsCerts) {
    Build-Target 'rdns-certs' './tools/rdns-certs' 'windows' 'amd64'
}

# Reset env so later go commands on this shell behave normally.
$env:CGO_ENABLED = ''; $env:GOOS = ''; $env:GOARCH = ''

if ($fail -gt 0) {
    Write-Host "`n$fail build(s) FAILED" -ForegroundColor Red
    exit 1
}

# Checksums for verifying copies to the VPS.
Push-Location $dist
Get-ChildItem -File | Where-Object Name -ne 'SHA256SUMS.txt' | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$h  $($_.Name)"
} | Set-Content -Encoding ascii SHA256SUMS.txt
Pop-Location

Write-Host "`nall binaries in .\dist\  (manifest: SETUP.md section B)" -ForegroundColor Green
Write-Host "verify after copy:  sha256sum -c SHA256SUMS.txt`n"
