<#
.SYNOPSIS
    Builds the AVON agent MSI: both binaries, the pinned wintun.dll, and the
    WiX package — signed when a certificate is present.

.NOTES
    wintun.dll is verified before it is packaged. A SHA-256 can be pinned with
    -WintunSha256; with or without it the Authenticode signature must be valid
    and issued to WireGuard, so a tampered download never reaches the installer.
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$Out = "dist",
    [string]$WintunVersion = "0.14.1",
    [string]$WintunSha256 = "",
    [switch]$SkipSign
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("avon-msi-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $staging, $Out | Out-Null
try {
    cargo build --release --locked --target x86_64-pc-windows-msvc -p avon-agent --bin avon-agent
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    $rel = "target\x86_64-pc-windows-msvc\release"
    Copy-Item "$rel\avon-agent.exe" $staging
    Copy-Item "LICENSE" $staging

    # wintun.dll: download, verify, stage.
    $zip = Join-Path $staging "wintun.zip"
    Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-$WintunVersion.zip" -OutFile $zip
    if ($WintunSha256) {
        $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
        if ($actual -ne $WintunSha256.ToLower()) {
            throw "wintun-$WintunVersion.zip hash mismatch: got $actual, expected $WintunSha256"
        }
    }
    Expand-Archive -Path $zip -DestinationPath (Join-Path $staging "wintun-unpacked") -Force
    $dll = Get-ChildItem -Path (Join-Path $staging "wintun-unpacked") -Recurse -Filter wintun.dll |
        Where-Object { $_.FullName -match "amd64" } | Select-Object -First 1
    if (-not $dll) { throw "wintun.dll (amd64) not found in the archive" }
    $sig = Get-AuthenticodeSignature $dll.FullName
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "WireGuard") {
        throw "wintun.dll is not validly signed by WireGuard (status: $($sig.Status))"
    }
    Copy-Item $dll.FullName $staging

    if (-not $SkipSign -and $env:WINDOWS_CERT_PFX) {
        $pfx = Join-Path $staging "cert.pfx"
        [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:WINDOWS_CERT_PFX))
        foreach ($exe in @("avon-agent.exe")) {
            & signtool.exe sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
                /f $pfx /p $env:WINDOWS_CERT_PASSWORD (Join-Path $staging $exe)
            if ($LASTEXITCODE -ne 0) { throw "signtool failed for $exe" }
        }
    }

    $wixobj = Join-Path $staging "avon.wixobj"
    & candle.exe "deploy\windows\avon.wxs" -o $wixobj -ext WixUtilExtension `
        "-dVersion=$Version" "-dBinDir=$staging" "-dScriptDir=deploy\windows" -arch x64
    if ($LASTEXITCODE -ne 0) { throw "candle failed" }

    $msi = Join-Path $Out "avon-agent-$Version-x64.msi"
    & light.exe $wixobj -o $msi -ext WixUtilExtension -sval
    if ($LASTEXITCODE -ne 0) { throw "light failed" }

    if (-not $SkipSign -and $env:WINDOWS_CERT_PFX) {
        & signtool.exe sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
            /f (Join-Path $staging "cert.pfx") /p $env:WINDOWS_CERT_PASSWORD $msi
        if ($LASTEXITCODE -ne 0) { throw "signtool failed for the MSI" }
    }

    (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLower() + "  " + (Split-Path -Leaf $msi) |
        Set-Content -Path "$msi.sha256"
    Write-Host "built $msi"
}
finally {
    Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
}
